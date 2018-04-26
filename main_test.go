package gowebauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
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

type mockResponseWriter struct {
	Headers         http.Header
	Buff            *bytes.Buffer
	Status          int
	ForceErrOnWrite bool
}

func (rw mockResponseWriter) Header() http.Header {
	return rw.Headers
}

func (rw *mockResponseWriter) Write(data []byte) (int, error) {
	if rw.ForceErrOnWrite {
		return 0, errors.New("error writing to mockResponseWriter")
	}

	if rw.Buff == nil {
		rw.Buff = new(bytes.Buffer)
	}

	return rw.Buff.Write(data)
}

func (rw *mockResponseWriter) WriteHeader(status int) {
	rw.Status = status
}

func NewMockResponseWriter() *mockResponseWriter {
	rw := new(mockResponseWriter)
	rw.Headers = make(http.Header)
	rw.Buff = new(bytes.Buffer)
	rw.Status = 200

	return rw
}

// TestMakeUser tests the instantiation of `User` structs based on a variety
// of username and password pairings.
func TestMakeUser(t *testing.T) {
	var table = []struct {
		username string
		password string
	}{
		{"", ""},
		{"john", ""},
		{"", "password1"},
		{"john", "password1"},
		{"śpëçîāl", "čhàráçtęrś"},
	}

	for index, row := range table {
		user := MakeUser(row.username, row.password)

		// Check username
		if user.username != row.username {
			t.Errorf("for index %d: wanted username %v, but got %v", index, row.username, user.username)
		}

		// Check password
		if user.password != row.password {
			t.Errorf("for index %d: wanted password %v, but got %v", index, row.password, user.password)
		}
	}
}

// TestUser_IsAuthorized_MissingParts tests that an error is raised when
// trying to check user authentication when given an authentication string
// which doesnt follow the `<Scheme> <Token>` pattern.
func TestUser_IsAuthorized_MissingParts(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := base64.StdEncoding.EncodeToString([]byte("edward:p0nytail"))

	if err := user.IsAuthorized(authentication); err != errMalformedHeader {
		t.Errorf("wanted %v, but got %v", errMalformedHeader, err)
	}
}

// TestUser_IsAuthorized_BadScheme tests that an error is raised when
// trying to check user authentication when given an authentication string
// doesn't use the `Basic` scheme.
func TestUser_IsAuthorized_BadScheme(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Wrong " + base64.StdEncoding.EncodeToString([]byte("edward:p0nytail"))

	if err := user.IsAuthorized(authentication); err != errBadScheme {
		t.Errorf("wanted %v, but got %v", errBadScheme, err)
	}
}

// TestUser_IsAuthorized_Base64DecodeFail tests that an error is raised when
// trying to check user authentication when given an authentication string
// which fails on the base64 decoding.
func TestUser_IsAuthorized_Base64DecodeFail(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + hex.EncodeToString([]byte("edward:p0nytail"))

	if err := user.IsAuthorized(authentication); err != errBase64DecodeFailed {
		t.Errorf("wanted %v, but got %v", errBase64DecodeFailed, err)
	}
}

// TestUser_IsAuthorized_MalformedCredentials tests that an error is raised when
// trying to check user authentication when given an authentication string
// which contains a username and password which is not properly delimited.
func TestUser_IsAuthorized_MalformedCredentials(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + base64.StdEncoding.EncodeToString([]byte("edward p0nytail"))

	if err := user.IsAuthorized(authentication); err != errMalformedUsernamePassword {
		t.Errorf("wanted %v, but got %v", errMalformedUsernamePassword, err)
	}
}

// TestUser_IsAuthorized_BadCredentials tests that an error is raised when
// trying to check user authentication when given an authentication string
// which contains a username and password which are incorrect.
func TestUser_IsAuthorized_BadCredentials(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + base64.StdEncoding.EncodeToString([]byte("al:m3t@l"))

	if err := user.IsAuthorized(authentication); err != errFailedAuth {
		t.Errorf("wanted %v, but got %v", errFailedAuth, err)
	}
}

// TestUser_IsAuthorized tests IsAuthorized returns no error when a valid
// username and password pair is given in the correct format.
func TestUser_IsAuthorized_ValidCredentials(t *testing.T) {

	table := []struct {
		username string
		password string
	}{
		{"john", "snow"},
		{"jòhń", "śnöw"},
		{"username", ""},
		{"", "password"},
		{"", ""},
	}

	for _, row := range table {
		user := User{username: row.username, password: row.password}
		auth := "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(row.username+":"+row.password),
		)

		if err := user.IsAuthorized(auth); err != nil {
			t.Errorf("wanted %v, but got %v", nil, err)
		}
	}
}

// TestUser_FailureHandler_Panics tests that a panic is thrown from inside
// the handler in the event that writing to the response fails.
func TestUser_FailureHandler_Panics(t *testing.T) {
	defer func(t *testing.T) {
		err := recover()
		if err == nil {
			t.Errorf("wanted to panic, but it didn't happen")
		}
	}(t)

	authErr := errFailedAuth
	user := User{username: "gon", password: "hunter1"}

	handler := user.FailureHandler(authErr)
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	rw := NewMockResponseWriter()
	r := new(http.Request)

	rw.ForceErrOnWrite = true

	handler.ServeHTTP(rw, r)
	t.Errorf("should not reach this point")
}

// TestUser_FailureHandler_Success tests that a proper response is generated from
// the returned `http.Handler` function when given an authentication error.
func TestUser_FailureHandler_Success(t *testing.T) {
	authErr := errFailedAuth
	user := User{username: "gon", password: "hunter1"}

	handler := user.FailureHandler(authErr)
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

	if realm.Realm != realmName {
		t.Errorf("expected %v, but got %v", realmName, realm.Realm)
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
		err := realm.IsAuthorized(row.authentication)
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
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

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
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

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

// TestMiddleware_AuthError tests that a proper response is generated from
// the returned `http.Handler` function when given an authentication error.
func TestMiddleware_AuthError(t *testing.T) {
	authErr := errFailedAuth
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:creds"))

	rw := NewMockResponseWriter()
	r := new(http.Request)
	r.Header = http.Header{"Authorization": []string{auth}}

	middleware := Middleware(realm)

	route := func(w http.ResponseWriter, r *http.Request) {}

	handler := middleware(http.HandlerFunc(route))
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

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

// TestMiddleware_ValidAuth tests that a proper response is generated from
// the returned `http.Handler` function when no authentication error occurs.
func TestMiddleware_ValidAuth(t *testing.T) {
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("gon:hunter1"))

	rw := NewMockResponseWriter()
	r := new(http.Request)
	r.Header = http.Header{"Authorization": []string{auth}}

	middleware := Middleware(realm)

	route := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("body text"))
	}

	handler := middleware(http.HandlerFunc(route))
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	handler.ServeHTTP(rw, r)

	if rw.Status != 200 {
		t.Errorf("wanted status code 200, but got %v", rw.Status)
	}

	if rw.Buff.String() != "body text" {
		t.Errorf("invalid response body")
	}
}

// TestMiddleware_MissingAuth tests that a proper response is generated from
// the returned `http.Handler` function when no authentication is present.
func TestMiddleware_MissingAuth(t *testing.T) {
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	rw := NewMockResponseWriter()
	r := new(http.Request)

	middleware := Middleware(realm)
	route := func(w http.ResponseWriter, r *http.Request) {}

	handler := middleware(http.HandlerFunc(route))
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	handler.ServeHTTP(rw, r)

	if rw.Status != 401 {
		t.Errorf("wanted status code 401, but got %v", rw.Status)
	}
}

func TestHandle(t *testing.T) {
	user := MakeUser("śpëçîāl", "čhàráçtęrś")

	route := func(w http.ResponseWriter, r *http.Request) {}
	handler := Handle(user, route)

	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}
}

// TestMiddleware_AuthError tests that a proper response is generated from
// the returned `http.Handler` function when given an authentication error.
func TestHandlerFunc_AuthError(t *testing.T) {
	authErr := errFailedAuth
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:creds"))

	rw := NewMockResponseWriter()
	r := new(http.Request)
	r.Header = http.Header{"Authorization": []string{auth}}

	route := func(w http.ResponseWriter, r *http.Request) {}
	handler := HandlerFunc(realm, route)

	handler(rw, r)

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

// TestMiddleware_ValidAuth tests that a proper response is generated from
// the returned `http.Handler` function when no authentication error occurs.
func TestHandlerFunc_ValidAuth(t *testing.T) {
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("gon:hunter1"))

	rw := NewMockResponseWriter()
	r := new(http.Request)
	r.Header = http.Header{"Authorization": []string{auth}}

	route := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("body text"))
	}

	handler := HandlerFunc(realm, route)
	handler(rw, r)

	if rw.Status != 200 {
		t.Errorf("wanted status code 200, but got %v", rw.Status)
	}

	if rw.Buff.String() != "body text" {
		t.Errorf("invalid response body")
	}
}

// TestHandlerFunc_MissingAuth tests that a proper response is generated from
// the returned `http.Handler` function when no authentication is present.
func TestHandlerFunc_MissingAuth(t *testing.T) {
	realm := Realm{Realm: "Restricted", Charset: "utf-8", users: map[string]string{"gon": "hunter1"}}

	rw := NewMockResponseWriter()
	r := new(http.Request)

	route := func(w http.ResponseWriter, r *http.Request) {}
	handler := HandlerFunc(realm, route)
	if handler == nil {
		t.Errorf("wanted http.Handler, but got nil")
	}

	handler(rw, r)

	if rw.Status != 401 {
		t.Errorf("wanted status code 401, but got %v", rw.Status)
	}
}
