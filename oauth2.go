// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oauth2 provides support for making
// OAuth2 authorized and authenticated HTTP requests.
// It can additionally grant authorization with Bearer JWT.
//
// Example usage:
//
//      // Specify your configuration. (typically as a global variable)
//      config := oauth2.NewConfig(&oauth2.Options{
//              ClientID:     YOUR_CLIENT_ID,
//              ClientSecret: YOUR_CLIENT_SECRET,
//              RedirectURL:  "http://you.example.org/handler",
//              Scopes:       []string{ "scope1", "scope2" },
//      }, OAUTH2_PROVIDER_AUTH_URL, OAUTH2_PROVIDER_TOKEN_URL)
//
//      // A landing page redirects to the OAuth provider to get the auth code.
//      func landing(w http.ResponseWriter, r *http.Request) {
//              http.Redirect(w, r, config.AuthCodeURL("foo"), http.StatusFound)
//      }
//
//      // The user will be redirected back to this handler, that takes the
//      // "code" query parameter and Exchanges it for an access token.
//      func handler(w http.ResponseWriter, r *http.Request) {
//              t, err := config.NewTransportWithCode(r.FormValue("code"))
//              // The Transport now has a valid Token. Create an *http.Client
//              // with which we can make authenticated API requests.
//              c := t.Client()
//              c.Post(...)
//      }
//
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

// The default transport implementation to be used while
// making the authorized requests.
var DefaultTransport = http.DefaultTransport

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
	Cache() Cache
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
	conf := &Config{
		opts:     opts,
		authURL:  authURL,
		tokenURL: tokenURL,
	}
	if err := conf.validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

// Config represents the configuration of an OAuth 2.0 consumer client.
type Config struct {
	opts *Options
	// AuthURL is the URL the user will be directed to
	// in order to grant access.
	authURL string
	// TokenURL is the URL used to retrieve OAuth tokens.
	tokenURL string

	cache Cache
}

// Options returns options.
func (c *Config) Options() *Options {
	return c.opts
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
func (c *Config) AuthCodeURL(state string) (authURL string, err error) {
	u, err := url.Parse(c.authURL)
	if err != nil {
		return
	}
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
	return u.String(), nil
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
	return NewAuthorizedTransport(c, nil)
}

// NewTransportWithCode exchanges the OAuth 2.0 exchange code with
// the provider to fetch a new access token (and refresh token). Once
// it succesffully retrieves a new token, creates a new transport
// authorized with it.
func (c *Config) NewTransportWithCode(exchangeCode string) (Transport, error) {
	token, err := c.Exchange(exchangeCode)
	if err != nil {
		return nil, err
	}
	return NewAuthorizedTransport(c, token), nil
}

// Exchange exchanges the exchange code with the OAuth 2.0 provider
// to retrieve a new access token.
func (c *Config) Exchange(exchangeCode string) (*Token, error) {
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

// Cache returns a cache if specified, otherwise nil.
func (c *Config) Cache() Cache {
	return c.cache
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
	// TODO(jbd): Validate the URLs. Maybe convert them to URL
	// objects on construction.
	if c.authURL == "" {
		return errors.New("An auth URL should be provided.")
	}
	if c.tokenURL == "" {
		return errors.New("A token URL should be provided.")
	}
	return nil
}

func (c *Config) updateToken(tok *Token, v url.Values) error {
	v.Set("client_id", c.opts.ClientID)
	v.Set("client_secret", c.opts.ClientSecret)
	r, err := (&http.Client{Transport: DefaultTransport}).PostForm(c.tokenURL, v)
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
