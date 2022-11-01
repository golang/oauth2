// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientcredentials implements the OAuth2.0 "client credentials" token flow,
// also known as the "two-legged OAuth 2.0".
//
// This should be used when the client is acting on its own behalf or when the client
// is the resource owner. It may also be used when requesting access to protected
// resources based on an authorization previously arranged with the authorization
// server.
//
// See https://tools.ietf.org/html/rfc6749#section-4.4
package clientcredentials // import "github.com/cloudentity/oauth2/clientcredentials"

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/internal"
)

// Config describes a 2-legged OAuth2 flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string

	// Scope specifies optional requested permissions.
	Scopes []string

	// EndpointParams specifies additional parameters for requests to the token endpoint.
	EndpointParams url.Values

	// AuthStyle optionally specifies how the endpoint wants the
	// client ID & client secret sent. The zero value means to
	// auto-detect.
	AuthStyle oauth2.AuthStyle

	// PrivateKeyAuth stores configuration options for private_key_jwt
	// client authentication method described in OpenID Connect spec.
	PrivateKeyAuth advancedauth.PrivateKeyAuth

	// TLSAuth stores the configuration options for tls_client_auth and self_signed_tls_client_auth
	// client authentication methods described in RFC 8705
	TLSAuth advancedauth.TLSAuth
}

// Token uses client credentials to retrieve a token.
//
// The provided context optionally controls which HTTP client is used. See the oauth2.HTTPClient variable.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	return c.TokenSource(ctx).Token()
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary.
//
// The provided context optionally controls which HTTP client
// is returned. See the oauth2.HTTPClient variable.
//
// The returned Client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// Token refreshes the token by using a new client credentials request.
// tokens received this way do not include a refresh token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	v := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(c.conf.Scopes) > 0 {
		v.Set("scope", strings.Join(c.conf.Scopes, " "))
	}
	// not client_secret nor auto_detect
	if c.conf.AuthStyle > 2 {
		var err error
		cfg := advancedauth.Config{
			AuthStyle:      c.conf.AuthStyle,
			ClientID:       c.conf.ClientID,
			PrivateKeyAuth: c.conf.PrivateKeyAuth,
			TLSAuth:        c.conf.TLSAuth,
			TokenURL:       c.conf.TokenURL,
		}
		if err = advancedauth.ExtendUrlValues(v, cfg); err != nil {
			return nil, err
		}
		if c.ctx, err = advancedauth.ExtendContext(c.ctx, cfg); err != nil {
			return nil, err
		}
	}
	for k, p := range c.conf.EndpointParams {
		// Allow grant_type to be overridden to allow interoperability with
		// non-compliant implementations.
		if _, ok := v[k]; ok && k != "grant_type" {
			return nil, fmt.Errorf("oauth2: cannot overwrite parameter %q", k)
		}
		v[k] = p
	}
	tk, err := internal.RetrieveToken(c.ctx, c.conf.ClientID, c.conf.ClientSecret, c.conf.TokenURL, v, internal.AuthStyle(c.conf.AuthStyle))
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*oauth2.RetrieveError)(rErr)
		}
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
	}
	return t.WithExtra(tk.Raw), nil
}
