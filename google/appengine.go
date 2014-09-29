// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appengine,!appenginevm

package google

import (
	"net/http"

	"github.com/golang/oauth2"

	"appengine"
	"appengine/urlfetch"
)

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
func (c *AppEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	token, expiry, err := appengine.AccessToken(c.context, c.scopes...)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token,
		Expiry:      expiry,
	}, nil
}

func (c *AppEngineConfig) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return &urlfetch.Transport{Context: c.context}
}
