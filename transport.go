// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Transport is an [http.RoundTripper] that makes OAuth 2.0 HTTP requests,
// wrapping a base [http.RoundTripper] and adding an Authorization header
// with a token from the supplied [TokenSource].
//
// Transport is a low-level mechanism. Most code will use the
// higher-level [Config.Client] method instead.
//
// An [http.Client] that follows a redirect sends the new request through
// Transport too. The client drops the Authorization header from a redirect
// that leaves the domain of the original request (or a subdomain of it),
// but it does so before the request reaches Transport, which would put the
// token back. Transport therefore sends such a request with no token at
// all, as the client would, and keeps the token on a redirect within the
// original domain. It recognizes a redirect by the [http.Request.Response]
// field, which the client sets on every request it creates to follow one.
type Transport struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source TokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip authorizes and authenticates the request with an
// access token from Transport's Source.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	if t.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	if redirectedCrossDomain(req) {
		// The client already stripped the header; send the request as it is.
		reqBodyClosed = true
		return t.base().RoundTrip(req)
	}
	token, err := t.Source.Token()
	if err != nil {
		return nil, err
	}

	req2 := req.Clone(req.Context())
	token.SetAuthHeader(req2)

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

// redirectedCrossDomain reports whether req was created by an http.Client
// to follow a redirect chain that has left the domain of the request that
// started it. The client records the redirect response in req.Response, so
// following that chain back reaches the original request. Once any hop has
// left the original domain, every later hop counts as cross-domain as well,
// even one that returns to it: that is how net/http treats the Authorization
// header, and it stops a chain from carrying the token out through a host
// that merely passes it back.
//
// Hostnames are compared in lower case as they appear in the URLs. net/http
// also converts an internationalized hostname to its ASCII form first; a
// chain that mixes the two forms of one name is treated as cross-domain
// here, which withholds the token rather than sending it.
func redirectedCrossDomain(req *http.Request) bool {
	if req.Response == nil {
		return false
	}
	first := req
	for first.Response != nil && first.Response.Request != nil {
		first = first.Response.Request
	}
	if first.Response != nil {
		// A response in the chain has no Request, so the original request
		// cannot be reached. The RoundTripper contract does not require
		// Response.Request to be set; rather than trust a chain that cannot
		// be verified, assume it left the domain and send no token.
		return true
	}
	domain := strings.ToLower(first.URL.Hostname())
	for r := req; r != first; r = r.Response.Request {
		if !isDomainOrSubdomain(strings.ToLower(r.URL.Hostname()), domain) {
			return true
		}
	}
	return false
}

// isDomainOrSubdomain reports whether sub is a subdomain (or exact match) of
// the parent domain. It is the rule net/http applies when deciding whether a
// redirect may keep the Authorization header, copied from net/http/client.go.
// Both domains must already be in canonical form.
func isDomainOrSubdomain(sub, parent string) bool {
	if sub == parent {
		return true
	}
	// If sub contains a :, it's probably an IPv6 address (and is definitely not a hostname).
	// Don't check the suffix in this case, to avoid matching the contents of a IPv6 zone.
	// For example, "::1%.www.example.com" is not a subdomain of "www.example.com".
	if strings.ContainsAny(sub, ":%") {
		return false
	}
	// If sub is "foo.example.com" and parent is "example.com",
	// that means sub must end in "."+parent.
	// Do it without allocating.
	if !strings.HasSuffix(sub, parent) {
		return false
	}
	return sub[len(sub)-len(parent)-1] == '.'
}

var cancelOnce sync.Once

// CancelRequest does nothing. It used to be a legacy cancellation mechanism
// but now only logs on first use to warn that it's deprecated.
//
// Deprecated: use contexts for cancellation instead.
func (t *Transport) CancelRequest(req *http.Request) {
	cancelOnce.Do(func() {
		log.Printf("deprecated: golang.org/x/oauth2: Transport.CancelRequest no longer does anything; use contexts")
	})
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}
