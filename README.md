![](.github/gowebauth.png)

[![CircleCI](https://circleci.com/gh/clagraff/gowebauth/tree/master.svg?style=svg)](https://circleci.com/gh/clagraff/gowebauth/tree/master)
[![GoDoc](https://godoc.org/github.com/clagraff/gowebauth?status.svg)](https://godoc.org/github.com/clagraff/gowebauth)
[![Go Report Card](http://goreportcard.com/badge/clagraff/gowebauth)](http://goreportcard.com/report/clagraff/gowebauth)

# GO Web Auth
Go library for providing middleware for HTTP auth schemes.

## Examples
### Single-user Basic Auth
```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/clagraff/gowebauth"
	"github.com/nbari/violetear"
)

// route writes the requested URL to the HTTP response.
func route(w http.ResponseWriter, r *http.Request) {
	response := []byte(fmt.Sprintf("Successfully hit: %s", r.URL.String()))

	w.Write(response)
}

// main will setup a new HTTP server using gowebauth for authentication.
func main() {
	// Use whatever infrastructure you want. We use violetear only as an example.
	router := violetear.New()

	// Lets specifiy all valid users & create a realm for them
	admin := gowebauth.MakeUser("admin", "Password!")

	// Create middleware to be used by your router
	adminOnly := gowebauth.Handle(admin, route)

	router.Handle("/private", adminOnly, "GET")
	router.HandleFunc("/public", route, "GET")

	log.Panic(http.ListenAndServe(":8080", router))
}
```

### Users and Realms
```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/clagraff/gowebauth"
	"github.com/nbari/violetear"
)

// route writes the requested URL to the HTTP response.
func route(w http.ResponseWriter, r *http.Request) {
	response := []byte(fmt.Sprintf("Successfully hit: %s", r.URL.String()))

	w.Write(response)
}

// main will setup a new HTTP server using gowebauth for authentication.
func main() {
	// Use whatever infrastructure you want. We use violetear only as an example.
	router := violetear.New()

	// Lets specifiy all valid users & create a realm for them
	users := []gowebauth.User{
		gowebauth.MakeUser("admin", "Password!"),
		gowebauth.MakeUser("gon", "hunter123"),
		gowebauth.MakeUser("bennett", "qwop"),
	}
	realm := gowebauth.MakeRealm("Restricted Page", users...)

	// Wrap route to require authentication.
	privateRoute := gowebauth.Handle(realm, route)

	router.Handle("/private", privateRoute, "GET")
	router.HandleFunc("/public", route, "GET")

	log.Panic(http.ListenAndServe(":8080", router))
}
```


While any of the examples are running, you can try hitting a route using Curl:

```bash
$ curl -v -u admin:Password! localhost:8080/private
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
* Server auth using Basic with user 'admin'
> GET /private HTTP/1.1
> Host: localhost:8080
> Authorization: Basic YWRtaW46UGFzc3dvcmQh
> User-Agent: curl/7.54.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Thu, 26 Apr 2018 15:17:06 GMT
< Content-Length: 26
< Content-Type: text/plain; charset=utf-8
<
* Connection #0 to host localhost left intact
Successfully hit: /private 
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
