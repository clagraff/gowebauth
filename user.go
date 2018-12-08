package gowebauth

import (
	"encoding/base64"
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

// User represents a single HTTP Basic Auth username and password pair.
// Since the username and password of a User are non-exported, you should
// create a new User using MakeUser(username, password).
type User struct {
	username string
	password string
}

// MakeUser creates a new User instance with the specified username and
// plaintext password. Usernames containing any colon characters results in
// a panic.
func MakeUser(username, password string) User {
	if strings.Contains(username, ":") {
		panic("username cannot contain a colon")
	}

	return User{
		username: username,
		password: password,
	}
}

// IsAuthorized checks the authorization string for the Basic scheme and a
// username and password which match the current user.
func (user User) IsAuthorized(r *http.Request) (string, error) {
	authorization := r.Header.Get("Authorization")
	if len(authorization) <= 0 {
		return "", errMalformedHeader
	}

	authParts := strings.Split(authorization, " ")
	if len(authParts) != 2 {
		return "", errMalformedHeader
	}

	scheme := authParts[0]
	encodedCredentials := authParts[1]

	if strings.ToLower(scheme) != "basic" {
		return "", errBadScheme
	}

	credentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return "", errBase64DecodeFailed
	}

	credParts := strings.Split(string(credentials), ":")

	if len(credParts) != 2 {
		return "", errMalformedUsernamePassword
	}

	username := credParts[0]
	password := credParts[1]

	if user.username != username || user.password != password {
		return "", errFailedAuth
	}

	return username, nil
}

// FailureHandler reponds with a 401 HTTP code, the WWW-Authenticate header,
// and an error message for HTTP Basic Auth failed requests.
// The realm is set as Restricted with the character set of utf-8. To
// control these, use a Realm instead.
func (user User) FailureHandler(authErr error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headerMap := w.Header()
		headerMap.Set("WWW-Authenticate", `Basic realm="Restricted" charset="utf-8"`)

		errMsg := []byte(authErr.Error())

		w.WriteHeader(401)
		_, err := w.Write(errMsg)
		if err != nil {
			panic(err)
		}
	}

	return http.HandlerFunc(fn)
}
