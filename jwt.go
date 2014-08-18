// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	// Email is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	Email string `json:"email"`

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey []byte `json:"-"`

	// Scopes identify the level of access being requested.
	Scopes []string `json:"scopes"`
}

// NewJWTConfig creates a new configuration with the specified options
// and OAuth2 provider endpoint.
func NewJWTConfig(opts *JWTOptions, aud string) (*JWTConfig, error) {
	audURL, err := url.Parse(aud)
	if err != nil {
		return nil, err
	}
	parsedKey, err := parseKey(opts.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &JWTConfig{opts: opts, aud: audURL, key: parsedKey}, nil
}

// JWTConfig represents an OAuth 2.0 provider and client options to
// provide authorized transports with a Bearer JWT token.
type JWTConfig struct {
	opts *JWTOptions
	aud  *url.URL
	key  *rsa.PrivateKey
}

// NewTransport creates a transport that is authorize with the
// parent JWT configuration.
func (c *JWTConfig) NewTransport() *Transport {
	return NewTransport(http.DefaultTransport, c, &Token{})
}

// NewTransportWithUser creates a transport that is authorized by
// the client and impersonates the specified user.
func (c *JWTConfig) NewTransportWithUser(user string) *Transport {
	return NewTransport(http.DefaultTransport, c, &Token{Subject: user})
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
		Aud:   c.aud.String(),
	}

	if existing.Subject != "" {
		claimSet.Sub = existing.Subject
		// prn is the old name of sub. Keep setting it
		// to be compatible with legacy OAuth 2.0 providers.
		claimSet.Prn = existing.Subject
	}

	payload, err := jws.Encode(defaultHeader, claimSet, c.key)
	if err != nil {
		return
	}
	v := url.Values{}
	v.Set("grant_type", defaultGrantType)
	v.Set("assertion", payload)

	//  Make a request with assertion to get a new token.
	resp, err := http.DefaultClient.PostForm(c.aud.String(), v)
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

// parseKey converts the binary contents of a private key file
// to an *rsa.PrivateKey. It detects whether the private key is in a
// PEM container or not. If so, it extracts the the private key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func parseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("oauth2: private key is invalid")
	}
	return parsed, nil
}
