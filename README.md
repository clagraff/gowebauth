![](.github/gowebauth.png)

[![CircleCI](https://circleci.com/gh/clagraff/gowebauth/tree/master.svg?style=svg)](https://circleci.com/gh/clagraff/gowebauth/tree/master)
[![GoDoc](https://godoc.org/github.com/clagraff/gowebauth?status.svg)](https://godoc.org/github.com/clagraff/gowebauth)
[![Go Report Card](http://goreportcard.com/badge/clagraff/gowebauth)](http://goreportcard.com/report/clagraff/gowebauth)
[![cover.run](https://cover.run/go/github.com/clagraff/gowebauth.svg?style=flat&tag=golang-1.10)](https://cover.run/go?tag=golang-1.10&repo=github.com%2Fclagraff%2Fgowebauth)

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
	realm, err := gowebauth.MakeRealm("Restricted Page", users)
	if err != nil {
	    panic(err)
    }

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

### HTTP Digest Auth
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

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
	realm, err := gowebauth.MakeRealm("Restricted Page", users)
	if err != nil {
		panic(err)
	}
	digest := gowebauth.MakeDigest(realm, 15, 300*time.Second)

	// Wrap route to require authentication.
	privateRoute := gowebauth.Handle(digest, route)

	router.Handle("/private", privateRoute, "GET")
	router.HandleFunc("/public", route, "GET")

	log.Panic(http.ListenAndServe(":8080", router))
}
```

While this example is running, you can try hitting the route and formatting
the digest-auth string.

Your exact bash commands will be different as the generated `nonce` will vary.

```bash
$ curl -v localhost:8080/private
curl -v localhost:8080/private
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /private HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
>
< HTTP/1.1 401 Unauthorized
< Www-Authenticate: Basic realm="Restricted Page" charset="utf-8" nonce="ad8fa7b5"
< Date: Wed, 23 May 2018 16:30:19 GMT
< Content-Length: 29
< Content-Type: text/plain; charset=utf-8
<
* Connection #0 to host localhost left intact
malformed authorizationheader
```

```bash
$ echo -n "gon:Restricted Page:hunter123" | md5sum
f6def3aaf5ce8c891e4f74a95fcbf0a1  -
$ echo -n "GET:/private" | md5sum
fda2c070587e883e75df51c06f6c70d2  -
$ echo -n "f6def3aaf5ce8c891e4f74a95fcbf0a1:ad8fa7b5:fda2c070587e883e75df51c06f6c70d2" | md5sum
3a32bfdcd6ba445d611d297f085065c6  -
```

```bash
$ curl -v --header "Authorization: Digest username=\"gon\",realm=\"Restricted Page\",nonce=\"ad8fa7b5\",uri=\"/private\",qop=\"qop\",response=\"3a32bfdcd6ba445d611d297f085065c6\""  localhost:8080/private
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /private HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
> Authorization: Digest username="gon",realm="Restricted Page",nonce="ad8fa7b5",uri="/private",qop="qop",response="3a32bfdcd6ba445d611d297f085065c6"
>
< HTTP/1.1 200 OK
< Date: Wed, 23 May 2018 16:32:27 GMT
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
