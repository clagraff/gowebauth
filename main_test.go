package gowebauth

import (
	"bytes"
	"encoding/base64"
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
