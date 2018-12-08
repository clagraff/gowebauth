package gowebauth

import (
	"crypto/md5" // nolint: gosec
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

/*
MIT License

Copyright (c) 2018 Curtis La Graff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

const nonceKeyLength = 4

var src = rand.NewSource(time.Now().Unix())

// makeNonce creates a new nonce of random characters.
func makeNonce() string {
	rnd := rand.New(src)
	keys := make([]byte, nonceKeyLength)
	_, err := rnd.Read(keys)
	if err != nil {
		panic(err)
	}

	token := fmt.Sprintf("%x", keys)

	return token
}

type nonceEnvelope struct {
	token         string
	validUntil    time.Time
	remainingUses int
}

type nonceStore struct {
	cache         *sync.Map
	cacheRefresh  time.Duration
	nonceLifetime time.Duration
	usageLimit    int
}

func makeNonceStore(
	usageLimit int,
	nonceLifetime,
	cacheRefresh time.Duration,
) nonceStore {
	return nonceStore{
		cache:         new(sync.Map),
		cacheRefresh:  cacheRefresh,
		nonceLifetime: nonceLifetime,
		usageLimit:    usageLimit,
	}
}

func (store nonceStore) refresh() {
	now := time.Now().UTC()

	fn := func(key, value interface{}) bool {
		envelope := value.(nonceEnvelope)

		if envelope.validUntil.Before(now) {
			store.cache.Delete(key)
		} else if envelope.remainingUses == 0 {
			store.cache.Delete(key)
		}

		return true
	}

	store.cache.Range(fn)
}

func (store nonceStore) autoRefresh() func() {
	ticker := time.NewTicker(store.cacheRefresh)
	stop := ticker.Stop

	go func(s nonceStore, t *time.Ticker) {
		for range t.C {
			s.refresh()
		}
	}(store, ticker)

	return stop
}

func (store nonceStore) verify(token string) error {
	if store.cache == nil {
		return errors.New("store not properly initialized")
	}

	item, ok := store.cache.Load(token)
	if !ok {
		return errors.New("invalid nonce value")
	}

	envelope, ok := item.(nonceEnvelope)
	if !ok {
		return errors.New("invalid cache value")
	}

	if envelope.validUntil.Before(time.Now().UTC()) {
		store.cache.Delete(token)
		return errors.New("expired nonce")
	}

	if envelope.remainingUses <= 0 {
		store.cache.Delete(token)
		return errors.New("nonce used too many times")
	}

	envelope.remainingUses--

	store.cache.Store(token, envelope)

	return nil
}

func (store nonceStore) generate() (string, error) {
	if store.cache == nil {
		return "", errors.New("store not properly initialized")
	}

	now := time.Now().UTC()
	n := makeNonce()

	envelope := nonceEnvelope{
		token:         n,
		remainingUses: store.usageLimit,
		validUntil:    now.Add(store.nonceLifetime),
	}

	store.cache.Store(n, envelope)

	return n, nil
}

func md5HashParts(parts ...string) string {
	data := strings.Join(parts, ":")
	return md5Hash(data)
}

func md5Hash(data string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(data))) // nolint: gosec
}

// Digest represents a new HTTP Digest Authentication manager.
type Digest struct {
	realm Realm
	store nonceStore
}

// MakeDigest returns an instantiated Digest instance. Specify how many times
// a nonce can be used, and how long it will last. Expired nonces will
// be cleaned up automatically.
func MakeDigest(realm Realm, uses int, lifetime time.Duration) Digest {
	store := makeNonceStore(uses, lifetime, lifetime/8)
	go store.autoRefresh()

	return Digest{
		realm: realm,
		store: store,
	}
}

type digestResponse struct {
	digestURI string
	nonce     string
	realm     string
	response  string
	username  string
}

func digestResponseFromMap(params map[string]string) (digestResponse, error) {
	resp := digestResponse{}

	if digestURI, ok := params["uri"]; ok {
		resp.digestURI = digestURI
	} else {
		return resp, errors.New("missing digest uri")
	}

	if nonce, ok := params["nonce"]; ok {
		resp.nonce = nonce
	} else {
		return resp, errors.New("missing nonce")
	}

	if realm, ok := params["realm"]; ok {
		resp.realm = realm
	} else {
		return resp, errors.New("missing realm")
	}

	if response, ok := params["response"]; ok {
		resp.response = response
	} else {
		return resp, errors.New("missing response")
	}

	if username, ok := params["username"]; ok {
		resp.username = username
	} else {
		return resp, errors.New("missing username")
	}

	return resp, nil
}

func makeParamMap(authParam string) (map[string]string, error) {
	params := map[string]string{
		"username": "",
		"realm":    "",
		"nonce":    "",
		"uri":      "",
		"response": "",
	}

	sections := strings.Split(authParam, ",")
	if len(sections) < 5 {
		return params, errors.New("missing digest parameters")
	}

	for _, section := range sections {
		parts := strings.Split(section, "=")
		if len(parts) != 2 {
			return params, errors.New("bad digest param")
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		value = value[1 : len(value)-1] // trim double-quotes
		if _, ok := params[key]; ok {
			params[key] = value
		}
	}

	for key, value := range params {
		if len(value) <= 0 {
			return params, errors.New("empty digest param value for " + key)
		}
	}

	return params, nil
}

func (digest Digest) validateScheme(authorization string) error {
	if len(authorization) <= 0 {
		return errMalformedHeader
	}

	parts := strings.Split(authorization, " ")
	if len(parts) < 2 {
		return errMalformedHeader
	}

	if strings.ToLower(parts[0]) != "digest" {
		return errBadScheme
	}

	return nil
}

// IsAuthorized checks the authorization to determine if it is a valid
// HTTP Digest response.
func (digest Digest) IsAuthorized(r *http.Request) (string, error) {
	authorization := r.Header.Get("Authorization")
	if err := digest.validateScheme(authorization); err != nil {
		return "", err
	}

	parts := strings.Split(authorization, " ")
	body := strings.Join(parts[1:], " ")

	parameters, err := makeParamMap(body)
	if err != nil {
		return "", err
	}

	response, err := digestResponseFromMap(parameters)
	if err != nil {
		return "", err
	}

	if response.realm != digest.realm.Name {
		return "", errors.New("wrong realm")
	}

	if len(response.nonce) <= 0 {
		return "", errors.New("invalid nonce")
	}

	var password string
	var ok bool

	if password, ok = digest.realm.users[response.username]; !ok {
		return "", errors.New("user not found")
	}

	err = digest.store.verify(response.nonce)
	if err != nil {
		return "", err
	}

	firstHash := md5HashParts(
		response.username,
		digest.realm.Name,
		password,
	)

	secondHash := md5HashParts(
		r.Method,
		response.digestURI,
	)

	responseHash := md5HashParts(
		firstHash,
		response.nonce,
		secondHash,
	)

	if response.response == responseHash {
		return response.username, nil
	}

	return "", errors.New("failed auth")
}

// FailureHandler reponds with a 401 HTTP code, the WWW-Authenticate header,
// and an error message for HTTP Basic Auth failed requests.
func (digest Digest) FailureHandler(authErr error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headerMap := w.Header()

		nonce, err := digest.store.generate()
		if err != nil {
			panic(err)
		}

		authenticate := fmt.Sprintf(
			`Digest realm="%s" charset="%s" nonce="%s"`,
			digest.realm.Name,
			digest.realm.Charset,
			nonce,
		)

		headerMap.Set("WWW-Authenticate", authenticate)

		errMsg := []byte(authErr.Error())

		w.WriteHeader(401)
		_, err = w.Write(errMsg)
		if err != nil {
			panic(err)
		}
	}

	return http.HandlerFunc(fn)
}
