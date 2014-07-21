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
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tokenRespBody struct {
	AccessToken  string        `json:"access_token"`
	TokenType    string        `json:"token_type"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    time.Duration `json:"expires_in"`
	IdToken      string        `json:"id_token"`
}

// TokenFetcher refreshes or fetches a new access token from the
// provider. It should return an error if it's not capable of
// retrieving a token.
type TokenFetcher interface {
	// FetchToken retrieves a new access token for the provider.
	// If the implementation doesn't know how to retrieve a new token,
	// it returns an error.
	FetchToken(existing *Token) (*Token, error)
}

// Options represents options to provide OAuth 2.0 client credentials
// and access level. A sample configuration:
//
//    opts := &oauth2.Options{
//        ClientID: "<clientID>",
//        ClientSecret: "ad4364309eff",
//        RedirectURL: "https://homepage/oauth2callback",
//        Scopes: []string{"scope1", "scope2"},
//        AccessType: "offline", // retrieves a refresh token
//    }
//
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

	// Optional, identifies the level of access being requested.
	Scopes []string `json:"scopes"`

	// Optional, "online" (default) or "offline", no refresh token if "online"
	AccessType string `json:"omit"`

	// ApprovalPrompt indicates whether the user should be
	// re-prompted for consent. If set to "auto" (default) the
	// user will be prompted only if they haven't previously
	// granted consent and the code can only be exchanged for an
	// access token.
	// If set to "force" the user will always be prompted, and the
	// code can be exchanged for a refresh token.
	ApprovalPrompt string `json:"omit"`
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
	conf := &Config{opts: opts, authURL: aURL, tokenURL: tURL}
	if err = conf.validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

// Config represents the configuration of an OAuth 2.0 consumer client.
type Config struct {
	opts *Options
	// AuthURL is the URL the user will be directed to
	// in order to grant access.
	authURL *url.URL
	// TokenURL is the URL used to retrieve OAuth tokens.
	tokenURL *url.URL
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
func (c *Config) AuthCodeURL(state string) (authURL string) {
	u := *c.authURL
	q := url.Values{
		"response_type":   {"code"},
		"client_id":       {c.opts.ClientID},
		"redirect_uri":    {c.opts.RedirectURL},
		"scope":           {strings.Join(c.opts.Scopes, " ")},
		"state":           {state},
		"access_type":     {c.opts.AccessType},
		"approval_prompt": {c.opts.ApprovalPrompt},
	}.Encode()
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
//
// Example:
//     t, _ := c.NewTransport()
//     t.SetToken(validToken)
//
func (c *Config) NewTransport() Transport {
	return NewAuthorizedTransport(http.DefaultTransport, c, nil)
}

// NewTransportWithCode exchanges the OAuth 2.0 exchange code with
// the provider to fetch a new access token (and refresh token). Once
// it succesffully retrieves a new token, creates a new transport
// authorized with it.
func (c *Config) NewTransportWithCode(exchangeCode string) (Transport, error) {
	token, err := c.exchange(exchangeCode)
	if err != nil {
		return nil, err
	}
	return NewAuthorizedTransport(http.DefaultTransport, c, token), nil
}

// FetchToken retrieves a new access token and updates the existing token
// with the newly fetched credentials. If existing token doesn't
// contain a refresh token, it returns an error.
func (c *Config) FetchToken(existing *Token) (*Token, error) {
	if existing == nil || existing.RefreshToken == "" {
		return nil, errors.New("cannot fetch access token without refresh token.")
	}
	err := c.updateToken(existing, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {existing.RefreshToken},
	})
	return existing, err
}

// Checks if all required configuration fields have non-zero values.
func (c *Config) validate() error {
	if c.opts.ClientID == "" {
		return errors.New("A client ID should be provided.")
	}
	if c.opts.ClientSecret == "" {
		return errors.New("A client secret should be provided.")
	}
	// TODO(jbd): Are redirect URIs allowed to be a
	// non-value string in the spec?
	if c.opts.RedirectURL == "" {
		return errors.New("A redirect URL should be provided.")
	}
	return nil
}

// Exchange exchanges the exchange code with the OAuth 2.0 provider
// to retrieve a new access token.
func (c *Config) exchange(exchangeCode string) (*Token, error) {
	token := &Token{}
	err := c.updateToken(token, url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {c.opts.RedirectURL},
		"scope":        {strings.Join(c.opts.Scopes, " ")},
		"code":         {exchangeCode},
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *Config) updateToken(tok *Token, v url.Values) error {
	v.Set("client_id", c.opts.ClientID)
	v.Set("client_secret", c.opts.ClientSecret)
	r, err := http.DefaultClient.PostForm(c.tokenURL.String(), v)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		// TODO(jbd): Add status code or error message
		return errors.New("Error during updating token.")
	}

	resp := &tokenRespBody{}
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return err
		}
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return err
		}
		resp.AccessToken = vals.Get("access_token")
		resp.TokenType = vals.Get("token_type")
		resp.RefreshToken = vals.Get("refresh_token")
		resp.ExpiresIn, _ = time.ParseDuration(vals.Get("expires_in") + "s")
		resp.IdToken = vals.Get("id_token")
	default:
		if err = json.NewDecoder(r.Body).Decode(&resp); err != nil {
			return err
		}
		// The JSON parser treats the unitless ExpiresIn like 'ns' instead of 's' as above,
		// so compensate here.
		resp.ExpiresIn *= time.Second
	}
	tok.AccessToken = resp.AccessToken
	tok.TokenType = resp.TokenType
	// Don't overwrite `RefreshToken` with an empty value
	if resp.RefreshToken != "" {
		tok.RefreshToken = resp.RefreshToken
	}
	if resp.ExpiresIn == 0 {
		tok.Expiry = time.Time{}
	} else {
		tok.Expiry = time.Now().Add(resp.ExpiresIn)
	}
	if resp.IdToken != "" {
		if tok.Extra == nil {
			tok.Extra = make(map[string]string)
		}
		tok.Extra["id_token"] = resp.IdToken
	}
	return nil
}
