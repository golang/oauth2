// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appengine,!appenginevm

package google

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang/oauth2"

	"appengine"
	"appengine/urlfetch"
)

// mu protects multiple threads from attempting to fetch a token at the same time.
var mu sync.Mutex

// tokens implements a local cache of tokens to prevent hitting quota limits for appengine.AccessToken calls.
var tokens map[string]*oauth2.Token

func init() {
	tokens = make(map[string]*oauth2.Token)
}

// AppEngineConfig represents a configuration for an
// App Engine application's Google service account.
type AppEngineConfig struct {
	// Transport is the http.RoundTripper to be used
	// to construct new oauth2.Transport instances from
	// this configuration.
	Transport http.RoundTripper

	context appengine.Context
	scopes  []string

	// key is the map key used to look up the cached tokens for this set of scopes.
	key string
}

// NewAppEngineConfig creates a new AppEngineConfig for the
// provided auth scopes.
func NewAppEngineConfig(context appengine.Context, scopes ...string) *AppEngineConfig {
	return &AppEngineConfig{
		context: context,
		scopes:  scopes,
		key:     strings.Join(scopes, "_"),
	}
}

// NewTransport returns a transport that authorizes
// the requests with the application's service account.
func (c *AppEngineConfig) NewTransport() *oauth2.Transport {
	return oauth2.NewTransport(c.transport(), c, nil)
}

// FetchToken fetches a new access token for the provided scopes.
// Tokens are cached locally so that the app can scale without hitting quota limits
// by calling appengine.AccessToken too frequently.
func (c *AppEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	mu.Lock()
	defer mu.Unlock()
	if t, ok := tokens[c.key]; ok && !t.Expiry.Before(time.Now()) {
		return t, nil
	}
	delete(tokens, c.key)

	token, expiry, err := appengine.AccessToken(c.context, c.scopes...)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken: token,
		Expiry:      expiry,
	}
	tokens[c.key] = t
	return t, nil
}

func (c *AppEngineConfig) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return &urlfetch.Transport{Context: c.context}
}
