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
	"encoding/hex"
	"net/http"
	"testing"
)

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

	if _, err := user.IsAuthorized(authentication); err != errMalformedHeader {
		t.Errorf("wanted %v, but got %v", errMalformedHeader, err)
	}
}

// TestUser_IsAuthorized_BadScheme tests that an error is raised when
// trying to check user authentication when given an authentication string
// doesn't use the `Basic` scheme.
func TestUser_IsAuthorized_BadScheme(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Wrong " + base64.StdEncoding.EncodeToString([]byte("edward:p0nytail"))

	if _, err := user.IsAuthorized(authentication); err != errBadScheme {
		t.Errorf("wanted %v, but got %v", errBadScheme, err)
	}
}

// TestUser_IsAuthorized_Base64DecodeFail tests that an error is raised when
// trying to check user authentication when given an authentication string
// which fails on the base64 decoding.
func TestUser_IsAuthorized_Base64DecodeFail(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + hex.EncodeToString([]byte("edward:p0nytail"))

	if _, err := user.IsAuthorized(authentication); err != errBase64DecodeFailed {
		t.Errorf("wanted %v, but got %v", errBase64DecodeFailed, err)
	}
}

// TestUser_IsAuthorized_MalformedCredentials tests that an error is raised when
// trying to check user authentication when given an authentication string
// which contains a username and password which is not properly delimited.
func TestUser_IsAuthorized_MalformedCredentials(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + base64.StdEncoding.EncodeToString([]byte("edward p0nytail"))

	if _, err := user.IsAuthorized(authentication); err != errMalformedUsernamePassword {
		t.Errorf("wanted %v, but got %v", errMalformedUsernamePassword, err)
	}
}

// TestUser_IsAuthorized_BadCredentials tests that an error is raised when
// trying to check user authentication when given an authentication string
// which contains a username and password which are incorrect.
func TestUser_IsAuthorized_BadCredentials(t *testing.T) {
	user := User{username: "edward", password: "p0nyta1l"}
	authentication := "Basic " + base64.StdEncoding.EncodeToString([]byte("al:m3t@l"))

	if _, err := user.IsAuthorized(authentication); err != errFailedAuth {
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

		if username, err := user.IsAuthorized(auth); err != nil {
			t.Errorf("wanted %v, but got %v", nil, err)
		} else if username != row.username {
			t.Errorf("wanted %v, but got %v", row.username, username)
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
