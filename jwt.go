// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/oauth2/jws"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultHeader    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
)

// JWTOptions represents a OAuth2 client's crendentials to retrieve a
// Bearer JWT token.
type JWTOptions struct {
	// ClientID is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	Email string `json:"email"`

	// The path to the pem file. If you have a p12 file instead, you
	// can use `openssl` to export the private key into a pem file.
	// $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	// Pem file should contain your private key.
	PemFilename string `json:"pemfilename"`

	// Scopes identify the level of access being requested.
	Scopes []string `json:"scopes"`
}

// TODO(jbd): Add p12 support.

// NewJWTConfig creates a new configuration with the specified options
// and OAuth2 provider endpoint.
func NewJWTConfig(opts *JWTOptions, aud string) (*JWTConfig, error) {
	contents, err := ioutil.ReadFile(opts.PemFilename)
	if err != nil {
		return nil, err
	}
	return &JWTConfig{opts: opts, aud: aud, signature: contents}, nil
}

// JWTConfig represents an OAuth 2.0 provider and client options to
// provide authorized transports with a Bearer JWT token.
type JWTConfig struct {
	opts      *JWTOptions
	aud       string
	signature []byte
	cache     Cache
}

// Options returns JWT options.
func (c *JWTConfig) Options() *JWTOptions {
	return c.opts
}

// NewTransport creates a transport that is authorize with the
// parent JWT configuration.
func (c *JWTConfig) NewTransport() Transport {
	return NewAuthorizedTransport(c, &Token{})
}

// NewTransportWithUser creates a transport that is authorized by
// the client and impersonates the specified user.
func (c *JWTConfig) NewTransportWithUser(user string) Transport {
	return NewAuthorizedTransport(c, &Token{Subject: user})
}

// NewTransportWithCache initializes a transport by reading the initial
// token from the provided cache. If a token refreshing occurs, it
// writes the newly fetched token back to the cache.
func (c *JWTConfig) NewTransportWithCache(cache Cache) (Transport, error) {
	token, err := cache.Read()
	if err != nil {
		return nil, err
	}
	c.cache = cache
	return NewAuthorizedTransport(c, token), nil
}

// fetchToken retrieves a new access token and updates the existing token
// with the newly fetched credentials.
func (c *JWTConfig) FetchToken(existing *Token) (token *Token, err error) {

	if existing == nil {
		existing = &Token{}
	}

	claimSet := &jws.ClaimSet{
		Iss:   c.opts.Email,
		Scope: strings.Join(c.opts.Scopes, " "),
		Aud:   c.aud,
	}

	if existing.Subject != "" {
		claimSet.Sub = existing.Subject
		// prn is the old name of sub. Keep setting it
		// to be compatible with legacy OAuth 2.0 providers.
		claimSet.Prn = existing.Subject
	}

	payload, err := jws.Encode(defaultHeader, claimSet, c.signature)
	if err != nil {
		return
	}
	v := url.Values{}
	v.Set("grant_type", defaultGrantType)
	v.Set("assertion", payload)

	//  Make a request with assertion to get a new token.
	client := http.Client{Transport: DefaultTransport}
	resp, err := client.PostForm(c.aud, v)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// TODO(jbd): Provide more context about the response.
		return nil, errors.New("Cannot fetch token, response: " + resp.Status)
	}

	b := &tokenRespBody{}
	err = json.NewDecoder(resp.Body).Decode(b)
	if err != nil {
		return nil, err
	}

	token = &Token{
		AccessToken: b.AccessToken,
		TokenType:   b.TokenType,
		Subject:     existing.Subject,
	}

	if b.IdToken != "" {
		// decode returned id token to get expiry
		claimSet := &jws.ClaimSet{}
		claimSet, err = jws.Decode(b.IdToken)
		if err != nil {
			return
		}
		token.Expiry = time.Unix(claimSet.Exp, 0)
		return
	}

	token.Expiry = time.Now().Add(time.Duration(b.ExpiresIn) * time.Second)
	return
}

// Cache returns a cache if specified, otherwise nil.
func (c *JWTConfig) Cache() Cache {
	return c.cache
}
