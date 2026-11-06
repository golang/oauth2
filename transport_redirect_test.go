// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// TestTransportRedirect checks where the token goes when an http.Client
// follows a redirect through Transport.
//
// Both test servers listen on the loopback interface, but server A is
// addressed as "localhost" and server B as "127.0.0.1". net/http decides
// whether a redirect may keep the Authorization header by comparing
// hostnames, so that hop is cross-domain, whereas two httptest servers
// addressed by their URLs are both 127.0.0.1 and count as the same host. The
// control request, sent through a plain client with the header set once,
// confirms that net/http strips the header on this hop, so whatever reaches
// server B through Transport was added by Transport.
func TestTransportRedirect(t *testing.T) {
	const token = "secret"

	var mu sync.Mutex
	got := map[string]string{} // final path -> Authorization header received there
	record := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got[r.URL.Path] = r.Header.Get("Authorization")
	}
	received := func(path string) string {
		mu.Lock()
		defer mu.Unlock()
		return got[path]
	}

	var addrA string // server A, addressed as localhost
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bounce" {
			http.Redirect(w, r, addrA+"/back", http.StatusFound)
			return
		}
		record(w, r)
	}))
	defer serverB.Close()
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, addrA+"/stayed", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, serverB.URL+"/landed", http.StatusFound)
		case "/chain":
			http.Redirect(w, r, serverB.URL+"/bounce", http.StatusFound)
		default:
			record(w, r)
		}
	}))
	defer serverA.Close()
	u, err := url.Parse(serverA.URL)
	if err != nil {
		t.Fatal(err)
	}
	addrA = "http://localhost:" + u.Port()

	get := func(client *http.Client, path, header string) {
		t.Helper()
		req, err := http.NewRequest("GET", addrA+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
	}

	// Control: a header the caller set is dropped by net/http when the
	// redirect leaves the domain. If it is not, the hop is not cross-domain
	// on this machine and the cases below would measure nothing.
	get(http.DefaultClient, "/cross", "Bearer "+token)
	if h := received("/landed"); h != "" {
		t.Fatalf("control: net/http sent Authorization %q to another domain; the test cannot isolate Transport", h)
	}
	mu.Lock()
	got = map[string]string{}
	mu.Unlock()

	client := &http.Client{Transport: &Transport{Source: StaticTokenSource(&Token{AccessToken: token})}}
	tests := []struct {
		path, final, want string
	}{
		// A redirect within the domain keeps the token, as it does with net/http.
		{"/same", "/stayed", "Bearer " + token},
		// A redirect to another domain gets no token.
		{"/cross", "/landed", ""},
		// A chain that left the domain gets no token even where it comes back.
		{"/chain", "/back", ""},
	}
	for _, tt := range tests {
		get(client, tt.path, "")
		if h := received(tt.final); h != tt.want {
			t.Errorf("GET %s: the redirect target received Authorization %q, want %q", tt.path, h, tt.want)
		}
	}
}

func TestRedirectedCrossDomain(t *testing.T) {
	// chain builds the request an http.Client would hand to a RoundTripper
	// after following redirects through the given URLs, in order.
	chain := func(urls ...string) *http.Request {
		var req *http.Request
		for _, s := range urls {
			u, err := url.Parse(s)
			if err != nil {
				t.Fatal(err)
			}
			next := &http.Request{URL: u, Header: http.Header{}}
			if req != nil {
				next.Response = &http.Response{Request: req}
			}
			req = next
		}
		return req
	}
	// brokenChain is chain, but the Response that links the second URL to
	// the first has no Request, as a RoundTripper that does not set
	// Response.Request would produce. The original request is unreachable.
	brokenChain := func(urls ...string) *http.Request {
		req := chain(urls...)
		r := req
		for r.Response != nil && r.Response.Request != nil && r.Response.Request.Response != nil {
			r = r.Response.Request
		}
		r.Response = &http.Response{}
		return req
	}
	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"not a redirect", chain("https://example.com/a"), false},
		{"same host", chain("https://example.com/a", "https://example.com/b"), false},
		{"same host, different case", chain("https://Example.com/a", "https://example.COM/b"), false},
		{"subdomain", chain("https://example.com/a", "https://api.example.com/b"), false},
		{"parent domain", chain("https://api.example.com/a", "https://example.com/b"), true},
		{"other host", chain("https://example.com/a", "https://evil.example/b"), true},
		{"suffix that is not a subdomain", chain("https://example.com/a", "https://notexample.com/b"), true},
		{"left and came back", chain("https://example.com/a", "https://evil.example/b", "https://example.com/c"), true},
		{"ipv6 zone", chain("https://www.example.com/a", "https://[::1%25.www.example.com]/b"), true},
		{"last hop's Response has no Request", brokenChain("https://example.com/a", "https://evil.example/b"), true},
		{"middle hop's Response has no Request", brokenChain("https://example.com/a", "https://evil.example/b", "https://evil.example/c"), true},
	}
	for _, tt := range tests {
		if got := redirectedCrossDomain(tt.req); got != tt.want {
			t.Errorf("%s: redirectedCrossDomain = %v, want %v", tt.name, got, tt.want)
		}
	}
}
