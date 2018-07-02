// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"fmt"
	"testing"
	"time"
)

func TestSDKConfig(t *testing.T) {
	var helperCallCount int
	mockTokenFormat := "Token #%d"
	mockHelper := func() (*configHelperResp, error) {
		token := fmt.Sprintf(mockTokenFormat, helperCallCount)
		helperCallCount += 1
		return &configHelperResp{
			Credential: struct {
				AccessToken string `json:"access_token"`
				TokenExpiry string `json:"token_expiry"`
			}{
				AccessToken: token,
				TokenExpiry: time.Now().Format(time.RFC3339),
			},
		}, nil
	}
	mockConfig := &SDKConfig{mockHelper}
	for i := 0; i < 10; i++ {
		tok, err := mockConfig.Token()
		if err != nil {
			t.Errorf("Unexpected error reading a mock config helper response: %v", err)
		} else if got, want := tok.AccessToken, fmt.Sprintf(mockTokenFormat, i); got != want {
			t.Errorf("Got access token of %q; wanted %q", got, want)
		}
	}

	failingHelper := func() (*configHelperResp, error) {
		return nil, fmt.Errorf("mock config helper failure")
	}
	failingConfig := &SDKConfig{failingHelper}
	if tok, err := failingConfig.Token(); err == nil {
		t.Errorf("unexpected token response for failing helper: got %v", tok)
	}

	badTimestampHelper := func() (*configHelperResp, error) {
		return &configHelperResp{
			Credential: struct {
				AccessToken string `json:"access_token"`
				TokenExpiry string `json:"token_expiry"`
			}{
				AccessToken: "Fake token",
				TokenExpiry: "The time at which it expires",
			},
		}, nil
	}
	badTimestampConfig := &SDKConfig{badTimestampHelper}
	if tok, err := badTimestampConfig.Token(); err == nil {
		t.Errorf("unexpected token response for a helper that returns bad expiry timestamps: got %v", tok)
	}
}
