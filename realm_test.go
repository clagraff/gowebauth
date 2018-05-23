package gowebauth

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

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestMakeRealm_DuplicateUsers tests that an error is returned when trying
// to create a realm which is provided users with duplicated usernames.
func TestMakeRealm_DuplicateUsers(t *testing.T) {
	users := []User{
		{"", ""},
		{"john", ""},
		{"", "password1"},
		{"john", "password1"},
		{"śpëçîāl", "čhàráçtęrś"},
	}

	realmName := "My Super Secret Restricted Area"

	if _, err := MakeRealm(realmName, users); err != errDuplicateUsernames {
		t.Errorf("expected %v, but got %v", errDuplicateUsernames, err)
	}
}

// TestMakeRealm_NoUsers tests that an error is returned when trying
// to create a realm while not providing any users.
func TestMakeRealm_NoUsers(t *testing.T) {
	noUsers := []User{}
	realmName := "My Super Secret Restricted Area"

	if _, err := MakeRealm(realmName, noUsers); err != errNoRealmUsers {
		t.Errorf("expected %v, but got %v", errNoRealmUsers, err)
	}
}

// TestMakeRealm_UniqueUsers tests that the realm name, default charset, and
// user pool are all populated correctly.
func TestMakeRealm_UniqueUsers(t *testing.T) {
	users := []User{
		{"", "empty"},
		{"john", "password1"},
		{"śpëçîāl", "čhàráçtęrś"},
	}

	realmName := "My Super Secret Restricted Area"

	realm, err := MakeRealm(realmName, users)

	if err != nil {
		t.Errorf("expected %v, but got %v", nil, err)
	}

	if realm.Name != realmName {
		t.Errorf("expected %v, but got %v", realmName, realm.Name)
	}

	defaultCharset := "utf-8"

	if realm.Charset != defaultCharset {
		t.Errorf("expected %v, but got %v", defaultCharset, realm.Charset)
	}

	if len(realm.users) != len(users) {
		t.Errorf("expected %d users, but got %d users", len(users), len(realm.users))
	}
}

func TestRealm_IsAuthorized(t *testing.T) {
	users := []User{
		{"john", "password1"},
	}
	realmName := "Restricted area"

	realm, err := MakeRealm(realmName, users)
	if err != nil {
		t.Errorf("expected %v, but got %v", nil, err)
	}

	table := []struct {
		authentication string
		err            error
	}{
		{base64.StdEncoding.EncodeToString([]byte("john:password1")), errMalformedHeader},
		{"Wrong " + base64.StdEncoding.EncodeToString([]byte("john:password1")), errBadScheme},
		{"Basic john:password1", errBase64DecodeFailed},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("john password1")), errMalformedUsernamePassword},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:creds")), errFailedAuth},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("john:password1")), nil},
	}

	for index, row := range table {
		r := new(http.Request)
		r.Header = make(http.Header)
		r.Header.Set("Authorization", row.authentication)
		_, err := realm.IsAuthorized(r)
		if err != row.err {
			t.Errorf("for case %d: wanted %v, but got %v", index, row.err, err)
		}
	}
}

// TestRealm_FailureHandler_Panics tests that a panic is thrown from inside
// the handler in the event that writing to the response fails.
func TestRealm_FailureHandler_Panics(t *testing.T) {
	defer func(t *testing.T) {
		err := recover()
		if err == nil {
			t.Errorf("wanted to panic, but it didn't happen")
		}
	}(t)

	authErr := errFailedAuth
	realm := Realm{Name: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	handler := realm.FailureHandler(authErr)
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	rw := NewMockResponseWriter()
	r := new(http.Request)

	rw.ForceErrOnWrite = true

	handler.ServeHTTP(rw, r)
	t.Errorf("should not reach this point")
}

// TestRealm_FailureHandler_Success tests that a proper response is generated from
// the returned `http.Handler` function when given an authentication error.
func TestRealm_FailureHandler_Success(t *testing.T) {
	authErr := errFailedAuth
	realm := Realm{Name: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	handler := realm.FailureHandler(authErr)
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
		t.Errorf("wanted Www-authenticate in headers, but it wasnt present")
	} else if len(value) != 1 || value[0] != `Basic realm="Restricted" charset="utf-8"` {
		t.Errorf("WWW-Authenticate header value was not correct")
	}

	if rw.Buff.String() != authErr.Error() {
		t.Errorf("invalid response body")
	}
}
