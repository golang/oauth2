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

	// Private key to sign JWS payloads.
	PrivateKey *rsa.PrivateKey `json:"-"`

	// The path to a pem container that includes your private key.
	// If PrivateKey is set, this field is ignored.
	//
	// If you have a p12 file instead, you
	// can use `openssl` to export the private key into a pem file.
	// $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	// Pem file should contain your private key.
	PemFilename string `json:"pemfilename"`

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
	if opts.PrivateKey != nil {
		return &JWTConfig{opts: opts, aud: audURL, key: opts.PrivateKey}, nil
	}
	contents, err := ioutil.ReadFile(opts.PemFilename)
	if err != nil {
		return nil, err
	}
	parsedKey, err := parsePemKey(contents)
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
func (c *JWTConfig) NewTransport() Transport {
	return NewAuthorizedTransport(http.DefaultTransport, c, &Token{})
}

// NewTransportWithUser creates a transport that is authorized by
// the client and impersonates the specified user.
func (c *JWTConfig) NewTransportWithUser(user string) Transport {
	return NewAuthorizedTransport(http.DefaultTransport, c, &Token{Subject: user})
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

// parsePemKey parses the pem file to extract the private key.
// It returns an error if private key is not provided or the
// provided key is invalid.
func parsePemKey(key []byte) (*rsa.PrivateKey, error) {
	invalidPrivateKeyErr := errors.New("oauth2: private key is invalid")
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, invalidPrivateKeyErr
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, invalidPrivateKeyErr
	}
	return parsed, nil
}
