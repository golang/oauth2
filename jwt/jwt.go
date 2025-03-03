// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jwt implements the OAuth 2.0 JSON Web Token flow, commonly
// known as "two-legged OAuth 2.0".
// See: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultHeader    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
)

// Config holds the configuration for using JWT to fetch tokens.
type Config struct {
	Email          string
	PrivateKey     []byte
	PrivateKeyID   string
	Subject        string
	Scopes         []string
	TokenURL       string
	Expires        time.Duration
	Audience       string
	PrivateClaims  map[string]interface{}
	UseIDToken     bool
}

// TokenSource returns a JWT TokenSource using the configuration in c.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, jwtSource{ctx: ctx, conf: c})
}

// Client returns an HTTP client that adds Authorization headers with tokens obtained from c.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

type jwtSource struct {
	ctx  context.Context
	conf *Config
}

func (js jwtSource) Token() (*oauth2.Token, error) {
	// Validate config
	if err := js.validateConfig(); err != nil {
		return nil, err
	}

	// Parse private key
	pk, err := internal.ParseKey(js.conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Generate JWT payload
	claimSet, err := js.generateClaimSet()
	if err != nil {
		return nil, err
	}

	h := *defaultHeader
	h.KeyID = js.conf.PrivateKeyID
	payload, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JWT: %v", err)
	}

	// Request token
	return js.requestToken(payload)
}

func (js jwtSource) validateConfig() error {
	if js.conf.Email == "" {
		return errors.New("email is required")
	}
	if len(js.conf.PrivateKey) == 0 {
		return errors.New("private key is required")
	}
	if js.conf.TokenURL == "" {
		return errors.New("token URL is required")
	}
	return nil
}

func (js jwtSource) generateClaimSet() (*jws.ClaimSet, error) {
	claimSet := &jws.ClaimSet{
		Iss:           js.conf.Email,
		Scope:         strings.Join(js.conf.Scopes, " "),
		Aud:           js.conf.TokenURL,
		PrivateClaims: js.conf.PrivateClaims,
	}

	if js.conf.Subject != "" {
		claimSet.Sub = js.conf.Subject
		claimSet.Prn = js.conf.Subject
	}

	if js.conf.Expires > 0 {
		claimSet.Exp = time.Now().Add(js.conf.Expires).Unix()
	}

	if js.conf.Audience != "" {
		claimSet.Aud = js.conf.Audience
	}

	return claimSet, nil
}

func (js jwtSource) requestToken(payload string) (*oauth2.Token, error) {
	hc := oauth2.NewClient(js.ctx, nil)
	v := url.Values{
		"grant_type": {defaultGrantType},
		"assertion":  {payload},
	}

	resp, err := hc.PostForm(js.conf.TokenURL, v)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	}

	return js.parseTokenResponse(resp)
}

func (js jwtSource) parseTokenResponse(resp *http.Response) (*oauth2.Token, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %v", err)
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %v", err)
	}

	token := &oauth2.Token{
		AccessToken: tokenRes.AccessToken,
		TokenType:   tokenRes.TokenType,
		Expiry:      time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}

	if js.conf.UseIDToken {
		if tokenRes.IDToken == "" {
			return nil, errors.New("response missing ID token")
		}
		token.AccessToken = tokenRes.IDToken
	}

	return token, nil
}

// Helper functions for better debugging
func debugLog(msg string) {
	fmt.Println("DEBUG:", msg)
}

func infoLog(msg string) {
	fmt.Println("INFO:", msg)
}

func warnLog(msg string) {
	fmt.Println("WARNING:", msg)
}

func errorLog(msg string) {
	fmt.Println("ERROR:", msg)
}

// Additional notes to ensure code clarity and maintainability:
// 1. Proper documentation should be added to all exported functions.
// 2. Ensure this code adheres to the latest security practices.
// 3. Add more test cases to cover edge scenarios.
// 4. Future improvements could include support for additional JWT algorithms.

// End of file


