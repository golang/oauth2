// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
	"sync"
	"time"
)

const (
	defaultTokenType = "Bearer"
)

// Token represents the crendentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
type Token struct {
	// A token that authorizes and authenticates the requests.
	AccessToken string `json:"access_token"`

	// Identifies the type of token returned.
	TokenType string `json:"token_type,omitempty"`

	// A token that may be used to obtain a new access token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// The remaining lifetime of the access token.
	Expiry time.Time `json:"expiry,omitempty"`

	// Extra optionally contains extra metadata from the server
	// when updating a token. The only current key that may be
	// populated is "id_token". It may be nil and will be
	// initialized as needed.
	Extra map[string]string `json:"extra,omitempty"`

	// Subject is the user to impersonate.
	Subject string `json:"subject,omitempty"`
}

// Expired returns true if there is no access token or the
// access token is expired.
func (t *Token) Expired() bool {
	if t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Before(time.Now())
}

// Transport is an http.RoundTripper that makes OAuth 2.0 HTTP requests.
type Transport struct {
	fetcher       TokenFetcher
	origTransport http.RoundTripper

	mu    sync.RWMutex
	token *Token
}

// NewTransport creates a new Transport that uses the provided
// token fetcher as token retrieving strategy. It authenticates
// the requests and delegates origTransport to make the actual requests.
func NewTransport(origTransport http.RoundTripper, fetcher TokenFetcher, token *Token) *Transport {
	return &Transport{origTransport: origTransport, fetcher: fetcher, token: token}
}

// RoundTrip authorizes and authenticates the request with an
// access token. If no token exists or token is expired,
// tries to refresh/fetch a new token.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	token := t.Token()

	if token == nil || token.Expired() {
		// Check if the token is refreshable.
		// If token is refreshable, don't return an error,
		// rather refresh.

		if err := t.RefreshToken(); err != nil {
			return nil, err
		}
		token = t.Token()
	}

	// To set the Authorization header, we must make a copy of the Request
	// so that we don't modify the Request we were given.
	// This is required by the specification of http.RoundTripper.
	req = cloneRequest(req)
	typ := token.TokenType
	if typ == "" {
		typ = defaultTokenType
	}

	req.Header.Set("Authorization", typ+" "+token.AccessToken)

	// Make the HTTP request.
	return t.origTransport.RoundTrip(req)
}

// Token returns the token that authorizes and
// authenticates the transport.
func (t *Transport) Token() *Token {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.token == nil {
		return nil
	}
	return &Token{
		AccessToken:  t.token.AccessToken,
		TokenType:    t.token.TokenType,
		RefreshToken: t.token.RefreshToken,
		Expiry:       t.token.Expiry,
		Extra:        t.token.Extra,
		Subject:      t.token.Subject,
	}
}

// SetToken sets a token to the transport in a thread-safe way.
func (t *Transport) SetToken(v *Token) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.token = v
}

// RefreshToken retrieves a new token, if a refreshing/fetching
// method is known and required credentials are presented
// (such as a refresh token).
func (t *Transport) RefreshToken() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	token, err := t.fetcher.FetchToken(t.token)
	if err != nil {
		return err
	}

	t.token = token

	return nil
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}
