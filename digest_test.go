package gowebauth

import (
	"fmt"
	"net/http"
	"testing"
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

// TestmakeNonce tests to ensure a non-zero nonce string is created.
func TestMakeNonce(t *testing.T) {
	nonce := makeNonce()
	expectedLength := nonceKeyLength * 2

	if len(nonce) != expectedLength {
		t.Errorf("expected %v, but got %v", expectedLength, len(nonce))
	}
}

func TestMakeNonceStore(t *testing.T) {
	usageLimit := 3
	lifetime := time.Second * 3
	cacheDuration := time.Second * 7

	store := makeNonceStore(usageLimit, lifetime, cacheDuration)

	if store.cache == nil {
		t.Errorf("internal cache must not be nil")
	}

	if store.usageLimit != usageLimit {
		t.Errorf("wanted %v, but got %v", usageLimit, store.usageLimit)
	}

	if store.nonceLifetime != lifetime {
		t.Errorf("wanted %v, but got %v", lifetime, store.nonceLifetime)
	}

	if store.cacheRefresh != cacheDuration {
		t.Errorf("wanted %v, but got %v", cacheDuration, store.cacheRefresh)
	}
}

func TestNonceStore_verify_ValidNonce(t *testing.T) {
	validNonce := "thisIsMyNonce"
	second := time.Second * 1
	envelope := nonceEnvelope{
		token:         validNonce,
		remainingUses: 1,
		validUntil:    time.Now().UTC().Add(second),
	}

	store := makeNonceStore(1, second, second)
	store.cache.Store(validNonce, envelope)
	actual := store.verify(validNonce)

	if actual != nil {
		t.Errorf("wanted %v, but got %v", nil, actual)
	}
}

func TestNonceStore_verify_InvalidNonce(t *testing.T) {
	invalidNonce := "thisIsMyNonce"
	second := time.Second * 1

	store := makeNonceStore(1, second, second)
	actual := store.verify(invalidNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestNonceStore_verify_ExpiredNonce tests that an error is returned when
// attempting to validate a nonce that has been expired.
func TestNonceStore_verify_ExpiredNonce(t *testing.T) {
	expiredNonce := "thisIsMyNonce"
	second := time.Second * 1
	envelope := nonceEnvelope{
		token:         expiredNonce,
		remainingUses: 1,
		validUntil:    time.Now().UTC().Add(-1 * second),
	}

	store := makeNonceStore(1, second, second)
	store.cache.Store(expiredNonce, envelope)

	actual := store.verify(expiredNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

func TestNonceStore_verify_NoRemainingUses(t *testing.T) {
	expiredNonce := "thisIsMyNonce"
	second := time.Second * 1
	envelope := nonceEnvelope{
		token:         expiredNonce,
		remainingUses: 0,
		validUntil:    time.Now().UTC().Add(second),
	}

	store := makeNonceStore(1, second, second)
	store.cache.Store(expiredNonce, envelope)

	actual := store.verify(expiredNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestNonceStore_verify_NilCache tests that an error is returned when
// attempting to validate a nonce when the store's cache has not been
// initialized.
func TestNonceStore_verify_NilCache(t *testing.T) {
	nonce := "thisIsMyNonce"

	store := nonceStore{}
	actual := store.verify(nonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestNonceStore_generate_NilCache tests that an error is returned when
// attempting to generate a nonce when the store's cache has not been
// initialized.
func TestNonceStore_generate_NilCache(t *testing.T) {
	store := nonceStore{}
	nonce, err := store.generate()

	if err == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}

	if string(nonce) != "" {
		t.Errorf("wanted %v, but got %v", "", nonce)
	}
}

// TestNonceStore_generate_Valid tests that a nonce value and no error
// is returned from an properly initialized OneUseStore.
func TestNonceStore_generate_Valid(t *testing.T) {
	usageLimit := 3
	lifetime := time.Second * 3
	cacheDuration := time.Second * 7

	store := makeNonceStore(usageLimit, lifetime, cacheDuration)
	nonce, err := store.generate()

	if err != nil {
		t.Errorf("wanted %v, but got %v", nil, err)
	}

	if string(nonce) == "" {
		t.Errorf("wanted a non-empty nonce, but got %v", nonce)
	}
}

// TestNonceStore_refresh tests that expired stored nonces are removed from
// the cache, while all other nonces are left unchanged.
func TestNonceStore_refresh(t *testing.T) {
	usageLimit := 3
	lifetime := time.Second * 9
	cacheDuration := time.Second * 14
	store := makeNonceStore(usageLimit, lifetime, cacheDuration)

	validNonces := make([]string, 3)
	expiredNonces := make([]string, 7)
	usedUpNonces := make([]string, 5)

	for i := range validNonces {
		var err error

		validNonces[i], err = store.generate()
		if err != nil {
			panic(err)
		}
	}

	for i := range expiredNonces {
		nonce := makeNonce()
		expiredNonces[i] = nonce
		envelope := nonceEnvelope{
			token:         nonce,
			validUntil:    time.Now().UTC().Add(-1 * time.Second),
			remainingUses: 1,
		}
		store.cache.Store(nonce, envelope)
	}

	for i := range usedUpNonces {
		nonce := makeNonce()
		usedUpNonces[i] = nonce
		envelope := nonceEnvelope{
			token:         nonce,
			validUntil:    time.Now().UTC().Add(time.Second),
			remainingUses: 0,
		}
		store.cache.Store(nonce, envelope)
	}

	store.refresh()

	for _, nonce := range validNonces {
		if _, ok := store.cache.Load(nonce); !ok {
			t.Errorf("wanted %v, but could not be retrieved", nonce)
		}
	}

	for _, nonce := range expiredNonces {
		if _, ok := store.cache.Load(nonce); ok {
			t.Errorf("must not be able to retrieve nonce %v", nonce)
		}
	}

	for _, nonce := range usedUpNonces {
		if _, ok := store.cache.Load(nonce); ok {
			t.Errorf("must not be able to retrieve nonce %v", nonce)
		}
	}
}

// TestNonceStore_autoRefresh tests that expired stored nonces are removed from
// the cache, while all other nonces are left unchanged.
func TestNonceStore_autoRefresh(t *testing.T) {
	usageLimit := 1
	lifetime := time.Second * 5
	cacheDuration := time.Millisecond * 10
	store := makeNonceStore(usageLimit, lifetime, cacheDuration)

	validNonces := make([]string, 3)
	expiredNonces := make([]string, 7)

	for i := range validNonces {
		var err error

		validNonces[i], err = store.generate()
		if err != nil {
			panic(err)
		}
	}

	for i := range expiredNonces {
		nonce := makeNonce()
		expiredNonces[i] = nonce

		envelope := nonceEnvelope{
			token:         nonce,
			validUntil:    time.Now().UTC().Add(-5 * time.Second),
			remainingUses: 1,
		}
		store.cache.Store(nonce, envelope)
	}

	stop := store.autoRefresh()
	defer stop()
	time.Sleep(time.Second) // Wait long enough for autorefresh to occur

	for _, nonce := range validNonces {
		if _, ok := store.cache.Load(nonce); !ok {
			t.Errorf("wanted %v, but could not be retrieved", nonce)
		}
	}

	for _, nonce := range expiredNonces {
		if _, ok := store.cache.Load(nonce); ok {
			t.Errorf("must not be able to retrieve nonce %v", nonce)
		}
	}
}

// TestDigestResponseFromMap tests generating digestResponses from variously
// populated maps.
func TestDigestResponseFromMap(t *testing.T) {
	keys := []string{"uri", "nonce", "realm", "response", "username"}
	data := []string{
		"/data/index.html",
		"at43vat43v",
		"Restricted",
		"vamni4va4ga",
		"user@name.com",
	}

	testMap := make(map[string]string)

	_, err := digestResponseFromMap(testMap)
	if err == nil {
		t.Errorf("wanted an error, but got %v", err)
	}

	for i, key := range keys {
		val := data[i]
		testMap[key] = val

		_, err := digestResponseFromMap(testMap)
		if len(testMap) == len(keys) {
			if err != nil {
				t.Errorf("wanted %v, but got %v", nil, err)
			}
		} else {
			if err == nil {
				t.Errorf("wanted an error, but got %v", err)
			}
		}
	}
}

// TestMakeParamMap tests returning various errors from a variety of inputs.
func TestMakeParamMap(t *testing.T) {
	table := []struct {
		input       string
		shouldError bool
	}{
		{``, true},
		{`,,,,`, true},
		{`username="fizzbuzz",uri="/data/index.html"`, true},
		{`username=missing_quotes,,,,`, true},
		{`username="john",realm="restricted",nonce="123412",uri="/data/index.html",response="avawreawerva"`, false},
		{`one="1",two="2",three="3",four="4",five="5"`, true},
	}

	for _, row := range table {
		_, err := makeParamMap(row.input)
		if row.shouldError && err == nil {
			t.Errorf("wanted an error, but got nil")
		}
		if !row.shouldError && err != nil {
			t.Errorf("wanted nil, but got %v", err)
		}
	}
}

// TestMD5Hash tests that a valid md5 hash is returned for the given
// input strings.
func TestMD5Hash(t *testing.T) {
	table := []struct {
		input        string
		expectedHash string
	}{
		{"sup3rl33th@ck3r", "620ef61f31d2d90cab6f9b56d9cf9699"},
		{"what does the fox say?", "494bab7fda61cc073b99d7ee55d1585b"},
		{"it's over 9000!!!", "633d5ef5652221c4452d58b7ec60d080"},
	}

	for _, row := range table {
		actualHash := md5Hash(row.input)
		if row.expectedHash != actualHash {
			t.Errorf("wanted %v, but got %v", row.expectedHash, actualHash)
		}
	}
}

// TestMakeDigest tests to ensure a new digest instance is instantiated
// correctly.
func TestMakeDigest(t *testing.T) {
	realm := Realm{Name: "Restricted Realm"}

	digest := MakeDigest(realm, 1, 1*time.Second)

	if digest.realm.Name != realm.Name {
		t.Errorf("wanted %v, but got %v", realm, digest.realm)
	}

	if digest.store.cache == nil {
		t.Errorf("expected NonceStore but has nil")
	}
}

// TestDigest_FailureHandler tests that a proper response is generated from the
// returned hhtp.Handler function when given an authentication error.
func TestDigest_FailureHandler(t *testing.T) {
	user := MakeUser("Mufasa", "Circle Of Life")
	realm, err := MakeRealm("testrealm@host.com", []User{user})
	if err != nil {
		panic(err)
	}
	digest := MakeDigest(realm, 1, 1*time.Second)

	handler := digest.FailureHandler(errFailedAuth)
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	rw := NewMockResponseWriter()
	r := new(http.Request)

	handler.ServeHTTP(rw, r)
	if rw.Status != 401 {
		t.Errorf("wanted status code 401, but got %v", rw.Status)
	}

	if value, ok := rw.Headers["Www-Authenticate"]; !ok {
		t.Errorf("wanted Www-Authenticate in headers, but it was not present")
	} else {
		var storedNonce string
		digest.store.cache.Range(func(k, v interface{}) bool {
			storedNonce = k.(string)
			return false
		})

		authorization := fmt.Sprintf(
			`Digest realm="%s" charset="%s" nonce="%s"`,
			realm.Name,
			realm.Charset,
			storedNonce,
		)

		if len(value) != 1 {
			t.Errorf("wanted Www-Authorization, but got nothing")
		}

		actualAuthorization := value[0]
		if authorization != actualAuthorization {
			t.Errorf(
				"wanted: %v but got %v",
				authorization,
				actualAuthorization,
			)
		}
	}
}

// TestDigest_IsAuthorized_Valid tests to that a valid digest authorization
// results in returning the username and no error.
func TestDigest_IsAuthorized_Valid(t *testing.T) {
	user := MakeUser("Mufasa", "Circle Of Life")
	realm, err := MakeRealm("testrealm@host.com", []User{user})
	if err != nil {
		panic(err)
	}

	digest := MakeDigest(realm, 1, 1*time.Second)
	uri := "/dir/index.html"
	method := "GET"

	nonce, err := digest.store.generate()
	if err != nil {
		panic(err)
	}
	response := md5HashParts(
		md5HashParts(
			user.username,
			realm.Name,
			user.password,
		),
		string(nonce),
		md5HashParts(
			method,
			uri,
		),
	)

	authorization := fmt.Sprintf(`Digest username="%s",
										 realm="%s",
										 nonce="%s",
										 uri="%s",
										 response="%s"`,
		user.username,
		realm.Name,
		string(nonce),
		uri,
		response,
	)
	r := new(http.Request)
	r.Header = make(http.Header)
	r.Header.Set("Authorization", authorization)
	r.Method = method

	if username, err := digest.IsAuthorized(r); err != nil {
		t.Errorf("wanted %v, but got %v", nil, err)
	} else if username != user.username {
		t.Errorf("wanted %v, but got %v", user.username, username)
	}
}

// TestValidateScheme performs a table-test against the validateScheme function.
func TestValidateScheme(t *testing.T) {
	table := []struct {
		input          string
		expectingError bool
	}{
		{"", true},
		{"missing_spaces", true},
		{"basic auth", true},
		{"digest auth", false},
	}

	d := Digest{}

	for _, row := range table {
		errResult := d.validateScheme(row.input)
		if errResult == nil && row.expectingError {
			t.Errorf("wanted an error, but got %v", errResult)
		} else if errResult != nil && !row.expectingError {
			t.Errorf("wanted %v, but got %v", nil, errResult)
		}
	}
}
