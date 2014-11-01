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
	"appengine/memcache"
	"appengine/urlfetch"
)

// aeMemcache wraps the needed Memcache functionality to make it easy to mock
type aeMemcache struct{}

func (m *aeMemcache) Get(c appengine.Context, key string, tok *oauth2.Token) (*memcache.Item, error) {
	return memcache.Gob.Get(c, key, tok)
}

func (m *aeMemcache) Set(c appengine.Context, item *memcache.Item) error {
	return memcache.Gob.Set(c, item)
}

type memcacher interface {
	Get(c appengine.Context, key string, tok *oauth2.Token) (*memcache.Item, error)
	Set(c appengine.Context, item *memcache.Item) error
}

// memcacheGob enables mocking of the memcache.Gob calls for unit testing.
var memcacheGob memcacher = &aeMemcache{}

// accessTokenFunc enables mocking of the appengine.AccessToken call for unit testing.
var accessTokenFunc = appengine.AccessToken

// safetyMargin is used to avoid clock-skew problems.
// 5 minutes is conservative because tokens are valid for 60 minutes.
const safetyMargin = 5 * time.Minute

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
}

// NewAppEngineConfig creates a new AppEngineConfig for the
// provided auth scopes.
func NewAppEngineConfig(context appengine.Context, scopes ...string) *AppEngineConfig {
	return &AppEngineConfig{
		context: context,
		scopes:  scopes,
	}
}

// NewTransport returns a transport that authorizes
// the requests with the application's service account.
func (c *AppEngineConfig) NewTransport() *oauth2.Transport {
	return oauth2.NewTransport(c.transport(), c, nil)
}

// FetchToken fetches a new access token for the provided scopes.
// Tokens are cached locally and also with Memcache so that the app can scale
// without hitting quota limits by calling appengine.AccessToken too frequently.
func (c *AppEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	mu.Lock()
	defer mu.Unlock()
	key := ":" + strings.Join(c.scopes, "_")
	now := time.Now().Add(safetyMargin)
	if t, ok := tokens[key]; ok && !t.Expiry.Before(now) {
		return t, nil
	}
	delete(tokens, key)

	// Attempt to get token from Memcache
	tok := new(oauth2.Token)
	_, err := memcacheGob.Get(c.context, key, tok)
	if err == nil && !tok.Expiry.Before(now) {
		tokens[key] = tok // Save token locally
		return tok, nil
	}

	token, expiry, err := accessTokenFunc(c.context, c.scopes...)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken: token,
		Expiry:      expiry,
	}
	tokens[key] = t
	// Also back up token in Memcache
	if err = memcacheGob.Set(c.context, &memcache.Item{
		Key:        key,
		Value:      []byte{},
		Object:     *t,
		Expiration: expiry.Sub(now),
	}); err != nil {
		c.context.Errorf("unexpected memcache.Set error: %v", err)
	}
	return t, nil
}

func (c *AppEngineConfig) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return &urlfetch.Transport{Context: c.context}
}
