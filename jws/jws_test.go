// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jws_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang/oauth2/jws"
)

// 1024 bit PEM encoded RSA
const PRIVATE_KEY string = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDPcK7IhOV9mk7aXz+jcxdUoPiKUI17gmQ7UTCT9L50nTyP2Qbr\nunwqPWYU5/r+n2EQdb7kBo8Sau8ct6TzbIF2E4QNkoMvedknxA1kRL89Os+OXpKy\nTIyIi0ua1krWBaX3oLfHSlkvINudmQZ9v1C3oXRKba6L8htIm427i2ePBwIDAQAB\nAoGAGtQcBtsJQ0FdyWhgNqd/8PYQrvLUGZE3nWRWwAv7ReHAH2qWNo6b2GqwdSu7\njorWZuaTlbIzdtJVsoUd1E3IQF13JTV50ZRHQVSMJuwDx37k47euzyvMFwh9zYjg\nMh7aezjTLhMNBNRJ03PghaYRbFMglk+0oxck5ALxkHwtmKECQQD0igtMvx/MJUqg\npWzfAoHXYTHk4FKR55CAKoKwyIrfvMIM+gqWlI37OaczDUp+JI8HwgRkt1AzHPRj\nk5AtjxwNAkEA2SmHJYnbyXbOKeKbNooBf89qOwo9GSQ4Dl2uPAxpYTYaiUdf+OZW\n7du34yKXsRJ5aCLTnhRDueuCAuSuouMOYwJBANPYbzeab2qEd+U5ylpcKq2ypu23\no/CAYj+WFEggQ6bWOGnTh66xnVqhtIZWok0rULmQzAuQfyr4j4NgR8wgKVUCQE9D\noimofQm3DJ8rMD4i91MgcQTlwtFXcAKGXR9b5GbwKZVr8PLXmGkvZppIORgPxzKk\na5tqiCHnfUfzEm8v80MCQGKE3zodVtQfVXYxpbfer4za6lNzEWqY8FXZ4yR+lted\nmmGMi8/RM2yDWO8/3uAcwrJ4CyEIpJt/dhZa7jtyxA0=\n-----END RSA PRIVATE KEY-----\n"
const PUBLIC_KEY string = "-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPcK7IhOV9mk7aXz+jcxdUoPiK\nUI17gmQ7UTCT9L50nTyP2QbrunwqPWYU5/r+n2EQdb7kBo8Sau8ct6TzbIF2E4QN\nkoMvedknxA1kRL89Os+OXpKyTIyIi0ua1krWBaX3oLfHSlkvINudmQZ9v1C3oXRK\nba6L8htIm427i2ePBwIDAQAB\n-----END RSA PUBLIC KEY-----\n"

// example JWT taken from https://developers.google.com/wallet/digital/docs/jsreference
const EXAMPLE_JWT string = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
	"eyJleHAiOiAxMzA5OTkxNzY0LCAiYXVkIjogImdvb2cucGF5bWVudHMuaW5hcHAuYnV5SXRlbSIsICJpc3MiOiAiMTA4NzM2NjAzNTQ2MjAwOTQ3MTYiLCAic2VsbGVyRGF0YSI6ICJfc2VsbGVyX2RhdGFfIiwgIml0ZW1EZXNjcmlwdGlvbiI6ICJUaGUgc2FmZXRpZXN0IHdheSB0byBkaXNwbGF5IHlvdXIgZmxhaXIiLCAiaXRlbVByaWNlIjogIjMuOTkiLCAiaXNvQ3VycmVuY3lDb2RlIjogIlVTRCIsICJpYXQiOiAxMzA5OTkxMTY0LCAiaXRlbU5hbWUiOiAiU2FmZXR5bW91c2UgUGF0Y2gifQ." +
	"E1VH0T9DvQn4GdCjyVavnlurpx0iklQXlqeI1_tAMa8"

func TestDecode(t *testing.T) {
	claimSet, err := jws.Decode(EXAMPLE_JWT)
	if err != nil {
		t.Errorf("failed to decode JWT: %v", err)
	}
	if claimSet.Iss != "10873660354620094716" {
		t.Errorf("received iss = %v; want 10873660354620094716", claimSet.Iss)
	}
	if claimSet.Aud != "goog.payments.inapp.buyItem" {
		t.Errorf("received aud = %v; want goog.payments.inapp.buyItem", claimSet.Aud)
	}
	if claimSet.Exp != 1309991764 {
		t.Errorf("received exp = %v; want 1309991764", claimSet.Exp)
	}
	if claimSet.Iat != 1309991164 {
		t.Errorf("received iat = %v; want 1309991164", claimSet.Iat)
	}

	if claimSet.PrivateClaims["sellerData"] != "_seller_data_" {
		t.Errorf("received sellerData = %v; want _seller_data_", claimSet.PrivateClaims["sellerData"])
	}
	if claimSet.PrivateClaims["aud"] != nil {
		t.Errorf("found registered claim in private claims")
	}
}

func decodePublicKey(key string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(key))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return pub.(*rsa.PublicKey)
}

func TestValidate(t *testing.T) {
	key := decodePublicKey(PUBLIC_KEY)
	var tests = []struct {
		claimSet jws.ClaimSet
		audience string
		valid    bool
		message  string
	}{
		{
			claimSet: jws.ClaimSet{Iss: "just.me", PrivateClaims: map[string]interface{}{"email": "joe@example.com"}},
			audience: "",
			valid:    true,
			message:  "",
		},
		{
			claimSet: jws.ClaimSet{Iss: "just.me", Exp: time.Now().Unix()},
			audience: "",
			valid:    false,
			message:  "token expired",
		},
		{
			claimSet: jws.ClaimSet{Iss: "just.me", Aud: "joe.blogs"},
			audience: "jack.blogs",
			valid:   false,
			message: "audience mismatch",
		},
		// TODO: add support for "nbf" (Not Before) claim
	}
	for _, test := range tests {
		header := jws.Header{Algorithm: "RS256"}
		jwt, err := jws.Encode(&header, &test.claimSet, []byte(PRIVATE_KEY))
		if err != nil {
			t.Fatal(err)
		}
		err = jws.Validate(jwt, key, test.audience)
		if test.valid && err != nil {
			t.Error(err)
		} else if !test.valid && err == nil {
			t.Errorf("did not receive expected error: %v", test.message)
		}
	}
}
