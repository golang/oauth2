// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"time"
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

func (ts tokenSource) impersonate() (*oauth2.Token, error) {
	reqBody := generateAccessTokenReq{
		Lifetime: "3600s",
		Scope:    ts.conf.Scopes,
	}
	b, err := json.Marshal(reqBody)

	serviceAccountImpersonationURL := ts.conf.ServiceAccountImpersonationURL
	ts.conf.ServiceAccountImpersonationURL = ""
	ts.conf.Scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

	client := oauth2.NewClient(ts.ctx, ts)
	if err != nil {
		return &oauth2.Token{}, fmt.Errorf("google: unable to marshal request: %v", err)
	}
	req, err := http.NewRequest("POST", serviceAccountImpersonationURL, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("impersonate: unable to create request: %v", err)
	}
	req = req.WithContext(ts.ctx)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("impersonate: unable to generate access token: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("impersonate: unable to read body: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("impersonate: status code %d: %s", c, body)
	}

	var accessTokenResp impersonateTokenResponse
	if err := json.Unmarshal(body, &accessTokenResp); err != nil {
		return nil, fmt.Errorf("impersonate: unable to parse response: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, accessTokenResp.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("impersonate: unable to parse expiry: %v", err)
	}
	return &oauth2.Token{
		AccessToken: accessTokenResp.AccessToken,
		Expiry:      expiry,
		TokenType:   "Bearer",
	}, nil

}
