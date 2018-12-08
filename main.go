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
	"context"
	"errors"
	"net/http"
)

var errMalformedHeader = errors.New("malformed authorizationheader")
var errBadScheme = errors.New("unsupported/missing authorization header scheme")
var errBase64DecodeFailed = errors.New(
	"failed decoding base64 authorization username:password",
)
var errMalformedUsernamePassword = errors.New("malformed username:password")
var errFailedAuth = errors.New("invalid username or password in authorization")
var errDuplicateUsernames = errors.New("duplicate username in realm")
var errNoRealmUsers = errors.New("realm doesnt contain any users")

type contextKey string

// ContextKey is the key used to store the identity from
// an IsAuthorized call into a request's context.Context.
// This is used for middleware and handlers.
var ContextKey = contextKey("Identity")

// Authorizer specifies an interface which enables performing authentication
// checks and providing an HTTP failure handler.
type Authorizer interface {
	IsAuthorized(*http.Request) (string, error)
	FailureHandler(error) http.Handler
}

// Middleware can be used with some web frameworks for creating authorization
// middleware.
// If a request fails to pass authorization, the authorizer's failure
// handler is used generate a response, and the request is no longer processed.
func Middleware(auth Authorizer) func(http.Handler) http.Handler {
	outter := func(next http.Handler) http.Handler {
		inner := func(w http.ResponseWriter, r *http.Request) {
			identifier, err := auth.IsAuthorized(r)

			if err != nil {
				auth.FailureHandler(err).ServeHTTP(w, r)
				return
			}

			updatedContext := context.WithValue(
				r.Context(),
				ContextKey,
				identifier,
			)

			next.ServeHTTP(w, r.WithContext(updatedContext))
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
		identifier, err := auth.IsAuthorized(r)

		if err != nil {
			auth.FailureHandler(err).ServeHTTP(w, r)
			return
		}

		updatedContext := context.WithValue(
			r.Context(),
			ContextKey,
			identifier,
		)

		fn(w, r.WithContext(updatedContext))
	}
}
