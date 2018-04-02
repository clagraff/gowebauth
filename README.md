![](.github/gowebauth.png)

[![CircleCI](https://circleci.com/gh/clagraff/gowebauth/tree/master.svg?style=svg)](https://circleci.com/gh/clagraff/gowebauth/tree/master)
[![GoDoc](https://godoc.org/github.com/clagraff/gowebauth?status.svg)](https://godoc.org/github.com/clagraff/gowebauth)
[![Go Report Card](http://goreportcard.com/badge/clagraff/gowebauth)](http://goreportcard.com/report/clagraff/gowebauth)

# GO Web Auth
Go library for providing middleware for HTTP auth schemes.

## Basic Auth
You can use HTTP Basic Auth in one of two fashions:
1. Use the `BasicAuth{}.Handler` function as middleware
2. Use the `BasicAuth{}.ServeHTTP` function

Both are demonstrated below:

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/clagraff/gowebauth"
	"github.com/nbari/violetear"
	"github.com/nbari/violetear/middleware"
)

func main() {
	router := violetear.New()

	auth := gowebauth.BasicAuth{Username: "johndoe", Password: "password123"}
	stdChain := middleware.New(auth.Handler)

	router.Handle("/foo", stdChain.ThenFunc(route), "GET")
	router.Handle("/", auth, "GET") // Return empty 200 on success, or 401 on error

	log.Fatal(http.ListenAndServe(":8080", router))
}

func route(w http.ResponseWriter, r *http.Request) {
	response := []byte(fmt.Sprintf("Successfully hit: %s", r.URL.String()))

	w.Write(response)
}
```

# License
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
