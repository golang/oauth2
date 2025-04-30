// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ParseKey converts the binary contents of a private key file
// to an [*rsa.PrivateKey]. It detects whether the private key is in a
// PEM container or not. If so, it extracts the private key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func ParseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKCS1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}

// addClientAuthnRequestParams adds client_secret_post client authentication
func addClientAuthnRequestParams(clientID, clientSecret string, v url.Values, authStyle AuthStyle) url.Values {
	if authStyle == AuthStyleInParams {
		v = cloneURLValues(v)
		if clientID != "" {
			v.Set("client_id", clientID)
		}
		if clientSecret != "" {
			v.Set("client_secret", clientSecret)
		}
	}
	return v
}

// addClientAuthnRequestHeaders adds client_secret_basic client authentication
func addClientAuthnRequestHeaders(clientID, clientSecret string, req *http.Request, authStyle AuthStyle) {
	if authStyle == AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
}

func NewRequestWithClientAuthn(httpMethod string, endpointURL, clientID, clientSecret string, v url.Values, authStyle AuthStyle) (*http.Request, error) {
	v = addClientAuthnRequestParams(clientID, clientSecret, v, authStyle)
	req, err := http.NewRequest(httpMethod, endpointURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	addClientAuthnRequestHeaders(clientID, clientSecret, req, authStyle)
	return req, nil
}
