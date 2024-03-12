// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package microsoft provides constants for using OAuth2 to access Windows Live ID.
package microsoft // import "golang.org/x/oauth2/microsoft"

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

// AzureADEndpoint returns a new oauth2.Endpoint for the given tenant at Azure Active Directory.
// If tenant is empty, it uses the tenant called `common`.
//
// For more information see:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
func AzureADEndpoint(tenant string) oauth2.Endpoint {
	if tenant == "" {
		tenant = "common"
	}
	return oauth2.Endpoint{
		AuthURL:  "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
	}
}

// Config is the configuration for using client credentials flow with a client assertion.
//
// For more information see:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT assertions.
	// PEM containers with a passphrase are not supported.
	// You can use pkcs12.Decode to extract the private key and certificate
	// from a PKCS #12 archive, or alternatively with OpenSSL:
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey []byte

	// Certificate contains the (optionally PEM encoded) X509 certificate registered
	// for the application with which you are authenticating.
	Certificate []byte

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string

	// TokenURL is the token endpoint. Typically you can use the AzureADEndpoint
	// function to obtain this value, but it may change for non-public clouds.
	TokenURL string

	// Expires optionally specifies how long the token is valid for.
	Expires time.Duration

	// Audience optionally specifies the intended audience of the
	// request.  If empty, the value of TokenURL is used as the
	// intended audience.
	Audience string
}

// TokenSource returns a TokenSource using the configuration
// in c and the HTTP client from the provided context.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, assertionSource{ctx, c})
}

// Client returns an HTTP client wrapping the context's
// HTTP transport and adding Authorization headers with tokens
// obtained from c.
//
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// assertionSource is a source that always does a signed request for a token.
// It should typically be wrapped with a reuseTokenSource.
type assertionSource struct {
	ctx  context.Context
	conf *Config
}

// Token refreshes the token by using a new client credentials request with signed assertion.
func (a assertionSource) Token() (*oauth2.Token, error) {
	crt := a.conf.Certificate
	if der, _ := pem.Decode(a.conf.Certificate); der != nil {
		crt = der.Bytes
	}
	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot parse certificate: %v", err)
	}
	s := sha1.Sum(cert.Raw)
	fp := base64.URLEncoding.EncodeToString(s[:])
	h := jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     fp,
	}

	claimSet := &jws.ClaimSet{
		Iss: a.conf.ClientID,
		Sub: a.conf.ClientID,
		Aud: a.conf.TokenURL,
	}
	if t := a.conf.Expires; t > 0 {
		claimSet.Exp = time.Now().Add(t).Unix()
	}
	if aud := a.conf.Audience; aud != "" {
		claimSet.Aud = aud
	}

	pk, err := internal.ParseKey(a.conf.PrivateKey)
	if err != nil {
		return nil, err
	}

	payload, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}

	hc := oauth2.NewClient(a.ctx, nil)
	v := url.Values{
		"client_assertion":      {payload},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_id":             {a.conf.ClientID},
		"grant_type":            {"client_credentials"},
		"scope":                 {strings.Join(a.conf.Scopes, " ")},
	}
	resp, err := hc.PostForm(a.conf.TokenURL, v)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
		ExpiresOn   int64  `json:"expires_on"` // timestamp
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	token := &oauth2.Token{
		AccessToken: tokenRes.AccessToken,
		TokenType:   tokenRes.TokenType,
	}
	if secs := tokenRes.ExpiresIn; secs > 0 {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	if v := tokenRes.IDToken; v != "" {
		// decode returned id token to get expiry
		claimSet, err := jws.Decode(v)
		if err != nil {
			return nil, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
		}
		token.Expiry = time.Unix(claimSet.Exp, 0)
	}

	return token, nil
}
