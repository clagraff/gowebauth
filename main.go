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

var errMissingHeader = errors.New("missing authorization header")
var errMalformedHeader = errors.New("malformed authorizationheader")
var errBadScheme = errors.New("unsupported/missing authorization header scheme")
var errBase64DecodeFailed = errors.New(
	"failed decoding base64 authorization username:password",
)
var errMalformedUsernamePassword = errors.New("malformed username:password")
var errFailedAuth = errors.New("invalid username or password in authorization")
var errDuplicateUsernames = errors.New("duplicate username in realm")
var errNoRealmUsers = errors.New("realm doesnt contain any users")

// Authorizer specifies an interface which enables performing authentication
// checks and providing an HTTP failure handler.
type Authorizer interface {
	IsAuthorized(string) error
	FailureHandler(error) http.Handler
}

// User represents a single HTTP Basic Auth username and password pair.
// Since the username and password of a `User` are non-exported, you should
// create a new `User` using `MakeUser(username, password)`.
type User struct {
	username string
	password string
}

// MakeUser creates a new `User` instance with the specified username and
// plaintext password.
func MakeUser(username, password string) User {
	return User{
		username: username,
		password: password,
	}
}

// IsAuthorized checks the authorization string for the `Basic` scheme and a
// username and password which match the current user.
func (user User) IsAuthorized(authorization string) error {
	authParts := strings.Split(authorization, " ")
	if len(authParts) != 2 {
		return errMalformedHeader
	}

	scheme := authParts[0]
	encodedCredentials := authParts[1]

	if strings.ToLower(scheme) != "basic" {
		return errBadScheme
	}

	credentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return errBase64DecodeFailed
	}

	credParts := strings.Split(string(credentials), ":")

	if len(credParts) != 2 {
		return errMalformedUsernamePassword
	}

	username := credParts[0]
	password := credParts[1]

	if user.username != username || user.password != password {
		return errFailedAuth
	}

	return nil
}

// FailureHandler reponds with a `401` HTTP code, the `WWW-Authenticate` header,
// and an error message for HTTP Basic Auth failed requests.
// The realm is set as `Restricted` with the character set of `utf-8`. To
// control these, use a `Realm` instead.
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

// Realm represents a collection of `Users` for a given HTTP Basic Auth realm.
type Realm struct {
	Charset string
	Realm   string
	users   map[string]string
}

// MakeRealm creates a new `Realm` instance for the given realm string and
// any applicable `User`s.
// This will default the `Realm`'s charset is `utf-8`.
// If no users are provided, or users share the same username, an error will
// occur.
func MakeRealm(realm string, users []User) (Realm, error) {
	auth := Realm{
		Charset: "utf-8",
		Realm:   realm,
		users:   make(map[string]string),
	}

	if len(users) == 0 {
		return auth, errNoRealmUsers
	}

	for _, user := range users {
		if _, ok := auth.users[user.username]; ok {
			return auth, errDuplicateUsernames
		}
		auth.users[user.username] = user.password
	}

	return auth, nil
}

// IsAuthorized checks the authorization string for a correct scheme &
// matching username and password for any of the users existing in the current
// realm.
func (realm Realm) IsAuthorized(authorization string) error {
	authParts := strings.Split(authorization, " ")
	if len(authParts) != 2 {
		return errMalformedHeader
	}

	scheme := authParts[0]
	encodedCredentials := authParts[1]

	if strings.ToLower(scheme) != "basic" {
		return errBadScheme
	}

	credentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return errBase64DecodeFailed
	}

	credParts := strings.Split(string(credentials), ":")

	if len(credParts) != 2 {
		return errMalformedUsernamePassword
	}

	requestUsername := credParts[0]
	requestPassword := credParts[1]

	if password, ok := realm.users[requestUsername]; ok {
		if requestPassword == password {
			return nil
		}
	}

	return errFailedAuth
}

// FailureHandler reponds with a `401` HTTP code, the `WWW-Authenticate` header,
// and an error message for HTTP Basic Auth failed requests.
func (realm Realm) FailureHandler(authErr error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		buff := bytes.NewBufferString("Basic")
		_, err := buff.WriteString(" realm=\"")
		if err != nil {
			panic(err)
		}

		if len(realm.Realm) > 0 {
			_, err = buff.WriteString(realm.Realm)
			if err != nil {
				panic(err)
			}
		}

		_, err = buff.WriteString("\"")
		if err != nil {
			panic(err)
		}

		charset := "utf-8"
		if len(realm.Charset) > 0 {
			charset = realm.Charset
		}

		_, err = buff.WriteString(" charset=\"")
		if err != nil {
			panic(err)
		}

		_, err = buff.WriteString(charset)
		if err != nil {
			panic(err)
		}

		_, err = buff.WriteString("\"")
		if err != nil {
			panic(err)
		}

		headerMap := w.Header()
		headerMap.Set("WWW-Authenticate", buff.String())

		errMsg := []byte(authErr.Error())

		w.WriteHeader(401)
		_, err = w.Write(errMsg)
		if err != nil {
			panic(err)
		}
	}

	return http.HandlerFunc(fn)
}

// Middleware can be used with some web frameworks for creating authorization
// middleware.
// If a request fails to pass authorization, the authorizer's failure
// handler is used generate a response, and the request is no longer processed.
func Middleware(auth Authorizer) func(http.Handler) http.Handler {
	outter := func(next http.Handler) http.Handler {
		inner := func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) <= 0 {
				auth.FailureHandler(errMissingHeader).ServeHTTP(w, r)
				return
			}

			err := auth.IsAuthorized(authHeader)
			if err != nil {
				auth.FailureHandler(err).ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(inner)
	}

	return outter
}

// Handle can be used with some web frameworks for creating authorization
// middleware.
// If a request fails to pass authorization, the authorizer's failure
// handler is used generate a response, and the request is no longer processed.
func Handle(
	auth Authorizer,
	fn func(http.ResponseWriter, *http.Request),
) http.Handler {
	return http.HandlerFunc(HandlerFunc(auth, fn))
}

// HandlerFunc can be used with some web frameworks for creating authorization
// middleware.
// If a request fails to pass authorization, the authorizer's failure
// handler is used generate a response, and the request is no longer processed.
func HandlerFunc(
	auth Authorizer,
	fn func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) <= 0 {
			auth.FailureHandler(errMissingHeader).ServeHTTP(w, r)
			return
		}

		err := auth.IsAuthorized(authHeader)
		if err != nil {
			auth.FailureHandler(err).ServeHTTP(w, r)
			return
		}

		fn(w, r)
	}
}
