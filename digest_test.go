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

// TestMakeNonce tests to ensure a non-zero nonce string is created.
func TestMakeNonce(t *testing.T) {
	nonce := MakeNonce()
	expectedLength := nonceKeyLength * 2

	if len(nonce) != expectedLength {
		t.Errorf("expected %v, but got %v", expectedLength, len(nonce))
	}
}

// TestMakeOneUseStore tests to ensure that a new OneUseStore is instantiated
// correctly.
func TestMakeOneUseStore(t *testing.T) {
	store := MakeOneUseStore()

	if store.cache == nil {
		t.Errorf("internal cache must not be nil")
	}
}

// TestOneUseStore_Verify_ValidNonce tests that a correct nonce can be validated
// correctly against a populated OneUseStore.
// A subsequent call should return an error as the nonce should no longer
// be available.
func TestOneUseStore_Verify_ValidNonce(t *testing.T) {
	validNonce := Nonce("thisIsMyNonce")

	store := MakeOneUseStore()
	store.cache.Store(validNonce, true)

	actual := store.Verify(validNonce)

	if actual != nil {
		t.Errorf("wanted %v, but got %v", nil, actual)
	}

	actual = store.Verify(validNonce)
	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestOneUseStore_Verify_InvalidNonce tests that an occur is returned when
// attempting to validate a nonce that does not exist within the store.
func TestOneUseStore_Verify_InvalidNonce(t *testing.T) {
	validNonce := Nonce("thisIsMyNonce")

	store := MakeOneUseStore()

	actual := store.Verify(validNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestOneUseStore_Verify_NilCache tests that an occur is returned when
// attempting to validate a nonce when the store's cache has not been
// initialized.
func TestOneUseStore_Verify_NilCache(t *testing.T) {
	validNonce := Nonce("thisIsMyNonce")

	store := OneUseStore{}
	actual := store.Verify(validNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestOneUseStore_Generate_NilCache tests that an occur is returned when
// attempting to generate a nonce when the store's cache has not been
// initialized.
func TestOneUseStore_Generate_NilCache(t *testing.T) {
	store := OneUseStore{}
	nonce, err := store.Generate()

	if err == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}

	if string(nonce) != "" {
		t.Errorf("wanted %v, but got %v", "", nonce)
	}
}

// TestOneUseStore_Generate_Valid tests that an a nonce value and no error
// is returned from an properly initialized OneUseStore.
func TestOneUseStore_Generate_Valid(t *testing.T) {
	store := MakeOneUseStore()
	nonce, err := store.Generate()

	if err != nil {
		t.Errorf("wanted %v, but got %v", nil, err)
	}

	if string(nonce) == "" {
		t.Errorf("wanted a non-empty nonce, but got %v", nonce)
	}
}

// TestMakeLimitedUseStore tests to ensure that a new LimitedUseStore is
// instantiated correctly.
func TestMakeLimitedUseStore(t *testing.T) {
	usageLimit := 5
	store := MakeLimitedUseStore(usageLimit)

	if store.cache == nil {
		t.Errorf("internal cache must not be nil")
	}

	if store.usageLimit != usageLimit {
		t.Errorf("wanted: %v, but got %v", usageLimit, store.usageLimit)
	}
}

// TestLimitedUseStore_Verify_ValidNonce tests that a correct nonce can be
// validated correctly against a populated LimitedUseStore.
// A subsequent call after all uses have been depleted should return an
// error as the nonce should no longer be available.
func TestLimitedUseStore_Verify_ValidNonce(t *testing.T) {
	validNonce := Nonce("thisIsMyNonce")

	usageLimit := 5
	store := MakeLimitedUseStore(usageLimit)
	store.cache.Store(validNonce, usageLimit)

	for i := 0; i < usageLimit; i++ {
		actual := store.Verify(validNonce)

		if actual != nil {
			t.Errorf("for index %v, wanted %v, but got %v", i, nil, actual)
		}
	}

	// Test that the none is no long valid
	actual := store.Verify(validNonce)
	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestLimitedUseStore_Verify_InvalidNonce tests that an occur is returned when
// attempting to validate a nonce that does not exist within the store.
func TestLimitedUseStore_Verify_InvalidNonce(t *testing.T) {
	invalidNonce := Nonce("thisIsMyNonce")

	usageLimit := 5
	store := MakeLimitedUseStore(usageLimit)

	actual := store.Verify(invalidNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestLimitedUseStore_Verify_NilCache tests that an occur is returned when
// attempting to validate a nonce when the store's cache has not been
// initialized.
func TestLimitedUseStore_Verify_NilCache(t *testing.T) {
	invalidNonce := Nonce("thisIsMyNonce")

	store := LimitedUseStore{}
	actual := store.Verify(invalidNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestLimitedUseStore_Generate_NilCache tests that an occur is returned when
// attempting to generate a nonce when the store's cache has not been
// initialized.
func TestLimitedUseStore_Generate_NilCache(t *testing.T) {
	store := LimitedUseStore{}
	nonce, err := store.Generate()

	if err == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}

	if string(nonce) != "" {
		t.Errorf("wanted %v, but got %v", "", nonce)
	}
}

// TestLimitedUseStore_Generate_Valid tests that an a nonce value and no error
// is returned from an properly initialized OneUseStore.
func TestLimitedUseStore_Generate_Valid(t *testing.T) {
	usageLimit := 5
	store := MakeLimitedUseStore(usageLimit)
	nonce, err := store.Generate()

	if err != nil {
		t.Errorf("wanted %v, but got %v", nil, err)
	}

	if string(nonce) == "" {
		t.Errorf("wanted a non-empty nonce, but got %v", nonce)
	}
}

// TestMakeTimeStore tests to ensure that a new TimeStore is instantiated
// correctly.
func TestMakeTimeStore(t *testing.T) {
	lifetime := time.Second * 3
	cacheDuration := time.Second * 7

	store := MakeTimeStore(lifetime, cacheDuration)

	if store.cache == nil {
		t.Errorf("internal cache must not be nil")
	}

	if store.lifetime != lifetime {
		t.Errorf("wanted %v, but got %v", lifetime, store.lifetime)
	}

	if store.cacheDuration != cacheDuration {
		t.Errorf("wanted %v, but got %v", cacheDuration, store.cacheDuration)
	}
}

// TestTimeStore_Verify_ValidNonce tests that a correct nonce can be validated
// correctly against a populated TimeStore.
func TestTimeStore(t *testing.T) {
	validNonce := Nonce("thisIsMyNonce")

	lifetime := time.Second * 3
	cacheDuration := time.Second * 7

	store := MakeTimeStore(lifetime, cacheDuration)
	store.cache.Store(validNonce, time.Now().UTC().Add(lifetime))

	actual := store.Verify(validNonce)

	if actual != nil {
		t.Errorf("wanted %v, but got %v", nil, actual)
	}
}

// TestTimeStore_Verify_InvalidNonce tests that an error is returned when
// attempting to validate a nonce that does not exist within the store.
func TestTimeStore_Verify_InvalidNonce(t *testing.T) {
	invalidNonce := Nonce("thisIsMyNonce")

	lifetime := time.Second * 3
	cacheDuration := time.Second * 4

	store := MakeTimeStore(lifetime, cacheDuration)
	actual := store.Verify(invalidNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestTimeStore_Verify_ExpiredNonce tests that an error is returned when
// attempting to validate a nonce that has been expired.
func TestTimeStore_Verify_ExpiredNonce(t *testing.T) {
	expiredNonce := Nonce("thisIsMyNonce")

	lifetime := time.Second * 3
	cacheDuration := time.Second * 4

	store := MakeTimeStore(lifetime, cacheDuration)
	store.cache.Store(expiredNonce, time.Now().UTC().Add(-1*time.Second))

	actual := store.Verify(expiredNonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestTimeStore_Verify_NilCache tests that an error is returned when
// attempting to validate a nonce when the store's cache has not been
// initialized.
func TestTimeStore_Verify_NilCache(t *testing.T) {
	nonce := Nonce("thisIsMyNonce")

	store := TimeStore{}
	actual := store.Verify(nonce)

	if actual == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}
}

// TestTimeStore_Generate_NilCache tests that an error is returned when
// attempting to generate a nonce when the store's cache has not been
// initialized.
func TestTimeStore_Generate_NilCache(t *testing.T) {
	store := TimeStore{}
	nonce, err := store.Generate()

	if err == nil {
		t.Errorf("wanted an error, but got %v", nil)
	}

	if string(nonce) != "" {
		t.Errorf("wanted %v, but got %v", "", nonce)
	}
}

// TestTimeStore_Generate_Valid tests that a nonce value and no error
// is returned from an properly initialized OneUseStore.
func TestTimeStore_Generate_Valid(t *testing.T) {
	lifetime := time.Second * 3
	cacheDuration := time.Second * 7

	store := MakeTimeStore(lifetime, cacheDuration)
	nonce, err := store.Generate()

	if err != nil {
		t.Errorf("wanted %v, but got %v", nil, err)
	}

	if string(nonce) == "" {
		t.Errorf("wanted a non-empty nonce, but got %v", nonce)
	}
}

// TestTimeStore_Refresh tests that expired stored nonces are removed from
// the cache, while all other nonces are left unchanged.
func TestTimeStore_Refresh(t *testing.T) {
	lifetime := time.Second * 9
	cacheDuration := time.Second * 14
	store := MakeTimeStore(lifetime, cacheDuration)

	validNonces := make([]Nonce, 3)
	expiredNonces := make([]Nonce, 7)

	for i := range validNonces {
		var err error

		validNonces[i], err = store.Generate()
		if err != nil {
			panic(err)
		}
	}

	for i := range expiredNonces {
		nonce := MakeNonce()
		expiredNonces[i] = nonce

		store.cache.Store(nonce, time.Now().UTC().Add(-1*time.Second))
	}

	store.Refresh()

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

// TestTimeStore_AutoRefresh tests that expired stored nonces are removed from
// the cache, while all other nonces are left unchanged.
func TestTimeStore_AutoRefresh(t *testing.T) {
	lifetime := time.Second * 5
	cacheDuration := time.Millisecond * 10
	store := MakeTimeStore(lifetime, cacheDuration)

	validNonces := make([]Nonce, 3)
	expiredNonces := make([]Nonce, 7)

	for i := range validNonces {
		var err error

		validNonces[i], err = store.Generate()
		if err != nil {
			panic(err)
		}
	}

	for i := range expiredNonces {
		nonce := MakeNonce()
		expiredNonces[i] = nonce

		store.cache.Store(nonce, time.Now().UTC().Add(-5*time.Second))
	}

	stop := store.AutoRefresh()
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
	store := OneUseStore{}

	digest := MakeDigest(realm, store)

	if digest.realm.Name != realm.Name {
		t.Errorf("wanted %v, but got %v", realm, digest.realm)
	}

	if digest.store != store {
		t.Errorf("wanted %v, but got %v", store, digest.store)
	}
}

// TestDigest_IsAuthorized_Valid tests to that a valid digest authorization
// results in returning the username and no error.
func TestDigest_IsAuthorized_Valid(t *testing.T) {
	store := MakeOneUseStore()
	user := MakeUser("Mufasa", "Circle Of Life")
	realm, err := MakeRealm("testrealm@host.com", []User{user})
	if err != nil {
		panic(err)
	}
	digest := MakeDigest(realm, store)
	uri := "/dir/index.html"
	method := "GET"

	nonce, err := store.Generate()
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
