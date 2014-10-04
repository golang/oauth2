// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package oauth2 provides support for making
// OAuth2 authorized and authenticated HTTP requests.
// It can additionally grant authorization with Bearer JWT.
package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type tokenRespBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // in seconds
	IdToken      string `json:"id_token"`
}

// TokenFetcher refreshes or fetches a new access token from the
// provider. It should return an error if it's not capable of
// retrieving a token.
type TokenFetcher interface {
	// FetchToken retrieves a new access token for the provider.
	// If the implementation doesn't know how to retrieve a new token,
	// it returns an error. The existing token may be nil.
	FetchToken(existing *Token) (*Token, error)
}

// Options represents options to provide OAuth 2.0 client credentials
// and access level. A sample configuration:
type Options struct {
	// ClientID is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	ClientID string `json:"client_id"`

	// ClientSecret is the OAuth client secret used when communicating with
	// the configured OAuth provider.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to which the user will be returned after
	// granting (or denying) access.
	RedirectURL string `json:"redirect_url"`

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string `json:"scopes,omitempty"`
}

// NewConfig creates a generic OAuth 2.0 configuration that talks
// to an OAuth 2.0 provider specified with authURL and tokenURL.
func NewConfig(opts *Options, authURL, tokenURL string) (*Config, error) {
	aURL, err := url.Parse(authURL)
	if err != nil {
		return nil, err
	}
	tURL, err := url.Parse(tokenURL)
	if err != nil {
		return nil, err
	}
	if opts.ClientID == "" {
		return nil, errors.New("oauth2: missing client ID")
	}
	return &Config{
		opts:     opts,
		authURL:  aURL,
		tokenURL: tURL,
	}, nil
}

// Config represents the configuration of an OAuth 2.0 consumer client.
type Config struct {
	// Client is the HTTP client to be used to retrieve
	// tokens from the OAuth 2.0 provider.
	Client *http.Client

	// Transport is the http.RoundTripper to be used
	// to construct new oauth2.Transport instances from
	// this configuration.
	Transport http.RoundTripper

	opts *Options
	// AuthURL is the URL the user will be directed to
	// in order to grant access.
	authURL *url.URL
	// TokenURL is the URL used to retrieve OAuth tokens.
	tokenURL *url.URL
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-zero string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
//
// Access type is an OAuth extension that gets sent as the
// "access_type" field in the URL from AuthCodeURL.
// It may be "online" (default) or "offline".
// If your application needs to refresh access tokens when the
// user is not present at the browser, then use offline. This
// will result in your application obtaining a refresh token
// the first time your application exchanges an authorization
// code for a user.
//
// Approval prompt indicates whether the user should be
// re-prompted for consent. If set to "auto" (default) the
// user will be prompted only if they haven't previously
// granted consent and the code can only be exchanged for an
// access token. If set to "force" the user will always be prompted,
// and the code can be exchanged for a refresh token.
func (c *Config) AuthCodeURL(state, accessType, prompt string) (authURL string) {
	u := *c.authURL
	v := url.Values{
		"response_type":   {"code"},
		"client_id":       {c.opts.ClientID},
		"redirect_uri":    condVal(c.opts.RedirectURL),
		"scope":           condVal(strings.Join(c.opts.Scopes, " ")),
		"state":           condVal(state),
		"access_type":     condVal(accessType),
		"approval_prompt": condVal(prompt),
	}
	q := v.Encode()
	if u.RawQuery == "" {
		u.RawQuery = q
	} else {
		u.RawQuery += "&" + q
	}
	return u.String()
}

// NewTransport creates a new authorizable transport. It doesn't
// initialize the new transport with a token, so after creation,
// you need to set a valid token (or an expired token with a valid
// refresh token) in order to be able to do authorized requests.
func (c *Config) NewTransport() *Transport {
	return NewTransport(c.transport(), c, nil)
}

// NewTransportWithCode exchanges the OAuth 2.0 authorization code with
// the provider to fetch a new access token (and refresh token). Once
// it successfully retrieves a new token, creates a new transport
// authorized with it.
func (c *Config) NewTransportWithCode(code string) (*Transport, error) {
	token, err := c.Exchange(code)
	if err != nil {
		return nil, err
	}
	return NewTransport(c.transport(), c, token), nil
}

// FetchToken retrieves a new access token and updates the existing token
// with the newly fetched credentials. If existing token doesn't
// contain a refresh token, it returns an error.
func (c *Config) FetchToken(existing *Token) (*Token, error) {
	if existing == nil || existing.RefreshToken == "" {
		return nil, errors.New("oauth2: cannot fetch access token without refresh token")
	}
	return c.retrieveToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {existing.RefreshToken},
	})
}

// Exchange exchanges the authorization code with the OAuth 2.0 provider
// to retrieve a new access token.
func (c *Config) Exchange(code string) (*Token, error) {
	return c.retrieveToken(url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": condVal(c.opts.RedirectURL),
		"scope":        condVal(strings.Join(c.opts.Scopes, " ")),
	})
}

func (c *Config) retrieveToken(v url.Values) (*Token, error) {
	v.Set("client_id", c.opts.ClientID)
	bustedAuth := !providerAuthHeaderWorks(c.tokenURL.String())
	if bustedAuth && c.opts.ClientSecret != "" {
		v.Set("client_secret", c.opts.ClientSecret)
	}
	req, err := http.NewRequest("POST", c.tokenURL.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !bustedAuth && c.opts.ClientSecret != "" {
		req.SetBasicAuth(c.opts.ClientID, c.opts.ClientSecret)
	}
	r, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := r.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	resp := &tokenRespBody{}
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		resp.AccessToken = vals.Get("access_token")
		resp.TokenType = vals.Get("token_type")
		resp.RefreshToken = vals.Get("refresh_token")
		resp.ExpiresIn, _ = strconv.ParseInt(vals.Get("expires_in"), 10, 64)
		resp.IdToken = vals.Get("id_token")
	default:
		if err = json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
	}
	token := &Token{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		RefreshToken: resp.RefreshToken,
	}
	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	if resp.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	if resp.ExpiresIn == 0 {
		token.Expiry = time.Time{}
	} else {
		token.Expiry = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	if resp.IdToken != "" {
		if token.Extra == nil {
			token.Extra = make(map[string]string)
		}
		token.Extra["id_token"] = resp.IdToken
	}
	return token, nil
}

func (c *Config) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return http.DefaultTransport
}

func (c *Config) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

func condVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// providerAuthHeaderWorks reports whether the OAuth2 server identified by the tokenURL
// implements the OAuth2 spec correctly
// See https://code.google.com/p/goauth2/issues/detail?id=31 for background.
// In summary:
// - Reddit only accepts client secret in the Authorization header
// - Dropbox accepts either it in URL param or Auth header, but not both.
// - Google only accepts URL param (not spec compliant?), not Auth header
func providerAuthHeaderWorks(tokenURL string) bool {
	if strings.HasPrefix(tokenURL, "https://accounts.google.com/") ||
		strings.HasPrefix(tokenURL, "https://github.com/") ||
		strings.HasPrefix(tokenURL, "https://api.instagram.com/") ||
		strings.HasPrefix(tokenURL, "https://www.douban.com/") ||
		strings.HasPrefix(tokenURL, "https://api.dropbox.com/") ||
		strings.HasPrefix(tokenURL, "https://api.soundcloud.com/") ||
		strings.HasPrefix(tokenURL, "https://www.linkedin.com/") {
		// Some sites fail to implement the OAuth2 spec fully.
		return false
	}

	// Assume the provider implements the spec properly
	// otherwise. We can add more exceptions as they're
	// discovered. We will _not_ be adding configurable hooks
	// to this package to let users select server bugs.
	return true
}
