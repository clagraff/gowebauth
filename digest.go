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

// Nonce represents a limited-user string token provided by the server.
type Nonce string

var src = rand.NewSource(time.Now().Unix())

// MakeNonce creates a new nonce of random characters.
func MakeNonce() Nonce {
	rnd := rand.New(src)
	keys := make([]byte, nonceKeyLength)
	_, err := rnd.Read(keys)
	if err != nil {
		panic(err)
	}

	token := fmt.Sprintf("%x", keys)

	return Nonce(token)
}

// NonceStore is an interface for providing new nonces and validating existing
// nonce.
type NonceStore interface {
	Verify(Nonce) error
	Generate() (Nonce, error)
}

// OneUseStore is an implementation of a NonceStore, where genereated nonces
// can only be validated once before being discarded.
// Subsequent verification attempts with a spent nonce results in an error.
type OneUseStore struct {
	cache *sync.Map
}

// MakeOneUseStore returns an instantiated OneUseStore instance.
func MakeOneUseStore() OneUseStore {
	return OneUseStore{cache: new(sync.Map)}
}

// Verify will check if the provided nonce currently exists in the store.
// If it does, remove it to prevent subsequent usages of it. Otherwise return
// an error.
func (store OneUseStore) Verify(token Nonce) error {
	if store.cache == nil {
		return errors.New("store not properly initialized")
	}

	_, ok := store.cache.Load(token)
	if !ok {
		return errors.New("invalid nonce value")
	}

	store.cache.Delete(token)
	return nil
}

// Generate will create a new one-time nonce and keep it in the store until
// it is later verified.
func (store OneUseStore) Generate() (Nonce, error) {
	if store.cache == nil {
		return Nonce(""), errors.New("store not properly initialized")
	}

	n := MakeNonce()
	store.cache.Store(n, true)

	return n, nil
}

// LimitedUseStore is an implementation of a NonceStore, where genereated nonces
// can only be validated N number of times before being discarded.
// Subsequent verification attempts with a spent nonce results in an error.
type LimitedUseStore struct {
	cache      *sync.Map
	usageLimit int
}

// MakeLimitedUseStore returns an instantiated LimitedUseStore instance.
func MakeLimitedUseStore(usageLimit int) LimitedUseStore {
	return LimitedUseStore{
		cache:      new(sync.Map),
		usageLimit: usageLimit,
	}
}

// Verify will check if the provided nonce currently exists in the store.
// If it does, decrease it's remaining usage amount; remove it if no more
// usages are available, thus preventing subsequent usages of it.
// Otherwise return an error if usage is no longer allowed or the nonce is not
// in the store.
func (store LimitedUseStore) Verify(token Nonce) error {
	if store.cache == nil {
		return errors.New("store not properly initialized")
	}

	remainingUses, ok := store.cache.Load(token)
	if !ok {
		return errors.New("invalid nonce value")
	}

	if amount, ok := remainingUses.(int); !ok || amount <= 1 {
		store.cache.Delete(token)
	} else {
		store.cache.Store(token, amount-1)
	}

	return nil
}

// Generate will create a new limited-usage nonce and keep it in the store until
// it is later verified.
func (store LimitedUseStore) Generate() (Nonce, error) {
	if store.cache == nil {
		return Nonce(""), errors.New("store not properly initialized")
	}

	n := MakeNonce()
	store.cache.Store(n, store.usageLimit)

	return n, nil
}

// TimeStore is an implementation of a NonceStore, where genereated nonces
// can only be validated for a specified period of time before being discarded.
// Subsequent verification attempts with an expired nonce results in an error.
type TimeStore struct {
	cache         *sync.Map
	lifetime      time.Duration
	cacheDuration time.Duration
}

// MakeTimeStore returns an instantiated TimeStore instance. The lifetime
// argument determines how long a nonce will remain valid for.
func MakeTimeStore(lifetime, cacheDuration time.Duration) TimeStore {
	return TimeStore{
		cache:         new(sync.Map),
		lifetime:      lifetime,
		cacheDuration: cacheDuration,
	}
}

// Refresh will invalidate and remove all expired nonces from the store. This
// should periodically be called to prevent uncontrolled memory usage from
// creating but not expiring old nonces.
func (store TimeStore) Refresh() {
	now := time.Now().UTC()

	clear := func(key, value interface{}) bool {
		if value.(time.Time).Before(now) {
			store.cache.Delete(key)
		}
		return true
	}
	store.cache.Range(clear)
}

// AutoRefresh is an alternative to Refresh, which will automatiaclly
// invalidate and remove all expired nonces. It runs concurrantly, but can
// be stopped by calling the returned function.
func (store TimeStore) AutoRefresh() func() {
	ticker := time.NewTicker(store.cacheDuration)
	stop := ticker.Stop

	go func(s TimeStore, t *time.Ticker) {
		for range t.C {
			s.Refresh()
		}
	}(store, ticker)

	return stop
}

// Verify will check if the provided nonce currently exists in the store and
// has not expired.
// If the nonce is expired, it is removed from the store completely and an
// error is returned. If no nonce can be found, an error is returned.
func (store TimeStore) Verify(token Nonce) error {
	if store.cache == nil {
		return errors.New("store not properly initialized")
	}

	nonce, ok := store.cache.Load(token)
	if !ok {
		return errors.New("invalid nonce value")
	}

	if nonce.(time.Time).Before(time.Now().UTC()) {
		store.cache.Delete(token)
		return errors.New("expired nonce")
	}

	return nil
}

// Generate will create a new time-limited nonce and keep it in the store until
// it is later verified.
func (store TimeStore) Generate() (Nonce, error) {
	if store.cache == nil {
		return Nonce(""), errors.New("store not properly initialized")
	}

	now := time.Now().UTC()
	n := MakeNonce()
	lifetime := now.Add(store.lifetime)

	store.cache.Store(n, lifetime)

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
	store NonceStore
}

// MakeDigest returns an instantiated Digest instance.
func MakeDigest(realm Realm, store NonceStore) Digest {
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

	err = digest.store.Verify(Nonce(response.nonce))
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

// FailureHandler reponds with a `401` HTTP code, the `WWW-Authenticate` header,
// and an error message for HTTP Basic Auth failed requests.
func (digest Digest) FailureHandler(authErr error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headerMap := w.Header()

		nonce, err := digest.store.Generate()
		if err != nil {
			panic(err)
		}

		authenticate := fmt.Sprintf(
			`Basic realm="%s" charset="%s" nonce="%s"`,
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
