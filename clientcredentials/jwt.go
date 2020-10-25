// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientcredentials

import (
	"crypto/rand"
	"math/big"
	"net/url"
	"time"

	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

var (
	defaultHeader = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
)

func randJWTID(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret = append(ret, letters[num.Int64()])
	}

	return string(ret), nil
}

func (c *tokenSource) jwtAssertionValues() (url.Values, error) {
	v := url.Values{
		"grant_type": {"client_credentials"},
	}
	pk, err := internal.ParseKey(c.conf.PrivateKey)
	if err != nil {
		return nil, err
	}
	claimSet := &jws.ClaimSet{
		Iss: c.conf.ClientID,
		Sub: c.conf.ClientID,
		Aud: c.conf.TokenURL,
	}

	claimSet.Jti, err = randJWTID(36)
	if err != nil {
		return nil, err
	}
	if t := c.conf.JWTExpires; t > 0 {
		claimSet.Exp = time.Now().Add(t).Unix()
	} else {
		claimSet.Exp = time.Now().Add(time.Hour).Unix()
	}

	h := *defaultHeader
	h.KeyID = c.conf.KeyID
	payload, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}
	v.Set("client_assertion", payload)
	v.Set("client_assertion_type", clientAssertionType)

	return v, nil
}
