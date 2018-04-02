package gowebauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
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

var ErrMissingHeader = errors.New("missing authorization header")
var ErrMalformedHeader = errors.New("malformed authorizationheader")
var ErrBadScheme = errors.New("unsupported/missing authorization header scheme")
var ErrBase64DecodeFailed = errors.New("failed decoding base64 authorization username:password")
var ErrMalformedUsernamePassword = errors.New("malformed username:password")
var ErrFailedAuth = errors.New("invalid username or password in authorization")

type BasicAuth struct {
	Username string
	Password string
	Realm    string
	Charset  string
}

func (auth BasicAuth) Authenticate(w http.ResponseWriter, r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= 0 {
		return ErrMissingHeader
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		return ErrMalformedHeader
	}

	scheme := authHeaderParts[0]
	authorization := authHeaderParts[1]

	if strings.ToLower(scheme) != "basic" {
		return ErrBadScheme
	}

	data, err := base64.StdEncoding.DecodeString(authorization)
	if err != nil {
		return ErrBase64DecodeFailed
	}

	authParts := strings.Split(string(data), ":")

	if len(authParts) != 2 {
		return ErrMalformedUsernamePassword
	}

	requestUsername := authParts[0]
	requestPassword := authParts[1]

	if auth.Username != requestUsername || auth.Password != requestPassword {
		return ErrFailedAuth
	}

	return nil
}

func (auth BasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := auth.Authenticate(w, r)
	if err != nil {
		auth.RequireAuthenticate(w)
	}
}

func (auth BasicAuth) RequireAuthenticate(w http.ResponseWriter) {
	buff := bytes.NewBufferString("Basic")
	if len(auth.Realm) > 0 {
		buff.WriteString(" realm=\"")
		buff.WriteString(auth.Realm)
		buff.WriteString("\"")
	}
	if len(auth.Charset) > 0 {
		buff.WriteString(" charset=\"")
		buff.WriteString(auth.Charset)
		buff.WriteString("\"")
	}

	headerMap := w.Header()
	headerMap.Set("WWW-Authenticate", buff.String())

	w.WriteHeader(401)
}

func (auth BasicAuth) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if err := auth.Authenticate(w, r); err != nil {
			auth.RequireAuthenticate(w)
			return
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
