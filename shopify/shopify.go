// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package shopify provides constants for using OAuth2 to access Shopify.
package shopify // import "golang.org/x/oauth2/shopify"

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"golang.org/x/oauth2"
)

// ShopEndpoint returns a new oauth2.Endpoint for the given shopify shop
// https://help.shopify.com/en/api/getting-started/authentication/oauth
func ShopEndpoint(shop string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  "https://" + shop + "/admin/oauth/authorize",
		TokenURL: "https://" + shop + "/admin/oauth/access_token",
	}
}

// VerifyRequest validates that the requested params come from shopify as signed
// with an hmac sha256 string against your api secret key - returns true/false
func VerifyRequest(r *http.Request, secret string) bool {
	values := r.URL.Query()

	// if there are no params sent or no hmac param sent at all, bad request
	if len(values) == 0 || len(values["hmac"]) < 1 {
		return false
	}

	hmacSig := values["hmac"][0]
	values.Del("hmac") // we compare the query without hmac param

	// the query string to generate an hmac compare on
	compareQuery := values.Encode()

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(compareQuery))

	sha := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(sha), []byte(hmacSig))
}
