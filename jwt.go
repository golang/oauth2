// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultHeader    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
)

// JWTConfig is the configuration for using JWT to fetch tokens,
// commonly known as "two-legged OAuth".
type JWTConfig struct {
	// Email is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	Email string

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey []byte

	// Subject is the optional user to impersonate.
	Subject string

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string

	// TokenURL is the endpoint required to complete the 2-legged JWT flow.
	TokenURL string
}

// TokenSource returns a JWT TokenSource using the configuration
// in c and the HTTP client from the provided context.
//
// The returned TokenSource only does JWT requests when necessary but
// otherwise returns the same token repeatedly until it expires.
//
// The provided initialToken may be nil, in which case the first
// call to TokenSource will do a new JWT request.
func (c *JWTConfig) TokenSource(ctx Context, initialToken *Token) TokenSource {
	return &newWhenNeededSource{
		t:   initialToken,
		new: jwtSource{ctx, c},
	}
}

// Client returns an HTTP client wrapping the context's
// HTTP transport and adding Authorization headers with tokens
// obtained from c.
//
// The provided initialToken may be nil, in which case the first
// call to TokenSource will do a new JWT request.
//
// The returned client and its Transport should not be modified.
func (c *JWTConfig) Client(ctx Context, initialToken *Token) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Base:   contextTransport(ctx),
			Source: c.TokenSource(ctx, initialToken),
		},
	}
}

// jwtSource is a source that always does a signed JWT request for a token.
// It should typically be wrapped with a newWhenNeededSource.
type jwtSource struct {
	ctx  Context
	conf *JWTConfig
}

func (js jwtSource) Token() (*Token, error) {
	pk, err := internal.ParseKey(js.conf.PrivateKey)
	if err != nil {
		return nil, err
	}
	hc, err := contextClient(js.ctx)
	if err != nil {
		return nil, err
	}
	claimSet := &jws.ClaimSet{
		Iss:   js.conf.Email,
		Scope: strings.Join(js.conf.Scopes, " "),
		Aud:   js.conf.TokenURL,
	}
	if subject := js.conf.Subject; subject != "" {
		claimSet.Sub = subject
		// prn is the old name of sub. Keep setting it
		// to be compatible with legacy OAuth 2.0 providers.
		claimSet.Prn = subject
	}
	payload, err := jws.Encode(defaultHeader, claimSet, pk)
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Set("grant_type", defaultGrantType)
	v.Set("assertion", payload)
	resp, err := hc.PostForm(js.conf.TokenURL, v)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", resp.Status, body)
	}
	b := make(map[string]interface{})
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	token := &Token{}
	token.AccessToken, _ = b["access_token"].(string)
	token.TokenType, _ = b["token_type"].(string)
	token.raw = b
	if e, ok := b["expires_in"].(float64); ok {
		token.Expiry = time.Now().Add(time.Duration(e) * time.Second)
	}
	if idtoken, ok := b["id_token"].(string); ok {
		// decode returned id token to get expiry
		claimSet, err := jws.Decode(idtoken)
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
		}
		token.Expiry = time.Unix(claimSet.Exp, 0)
		return token, nil
	}
	return token, nil
}
