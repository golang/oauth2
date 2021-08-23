// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// generateAccesstokenReq is used for service account impersonation
type generateAccessTokenReq struct {
	Delegates []string `json:"delegates,omitempty"`
	Lifetime  string   `json:"lifetime,omitempty"`
	Scope     []string `json:"scope,omitempty"`
}

type impersonateTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// ImpersonateTokenSource uses a source credential, stored in Ts, to request an access token to the provided Url
// Scopes can be defined when the access token is requested.
type ImpersonateTokenSource struct {
	// execution context
	Ctx context.Context
	// source credential
	Ts oauth2.TokenSource

	// impersonation url to request an access token
	Url string
	// scopes to include in the access token request
	Scopes []string
}

// Token performs the exchange to get a temporary service account token to allow access to GCP.
func (its ImpersonateTokenSource) Token() (*oauth2.Token, error) {
	reqBody := generateAccessTokenReq{
		Lifetime: "3600s",
		Scope:    its.Scopes,
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to marshal request: %v", err)
	}
	client := oauth2.NewClient(its.Ctx, its.Ts)
	req, err := http.NewRequest("POST", its.Url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to create impersonation request: %v", err)
	}
	req = req.WithContext(its.Ctx)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to generate access token: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to read body: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("oauth2/google: status code %d: %s", c, body)
	}

	var accessTokenResp impersonateTokenResponse
	if err := json.Unmarshal(body, &accessTokenResp); err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to parse response: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, accessTokenResp.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to parse expiry: %v", err)
	}
	return &oauth2.Token{
		AccessToken: accessTokenResp.AccessToken,
		Expiry:      expiry,
		TokenType:   "Bearer",
	}, nil
}
