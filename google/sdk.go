// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// configHelperResp corresponds to the JSON output of the `gcloud config-helper` command.
type configHelperResp struct {
	Credential struct {
		AccessToken string `json:"access_token"`
		TokenExpiry string `json:"token_expiry"`
	} `json:"credential"`
}

// An SDKConfig provides access to tokens from an account already
// authorized via the Google Cloud SDK.
type SDKConfig struct {
	// account is the name of the gcloud-authenticated account whose credentials should be used
	// to generate OAuth tokens. This should be one of the accounts listed in the output of
	// `gcloud auth list`.
	//
	// For instance, if the user logged in to gcloud with the account `user@example.com`, then
	// they could use `user@example.com` as the value for this field.
	account string
}

// NewSDKConfig creates an SDKConfig for the given Google Cloud SDK
// account. If account is empty, the account currently active in
// Google Cloud SDK properties is used.
// Google Cloud SDK credentials must be created by running `gcloud auth`
// before using this function.
// The Google Cloud SDK is available at https://cloud.google.com/sdk/.
func NewSDKConfig(account string) (*SDKConfig, error) {
	if account != "" {
		return &SDKConfig{account}, nil
	}
	cmd := exec.Command("gcloud", "auth", "list", "--filter=status=ACTIVE", "--format=value(account)")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("looking up the active Cloud SDK account: %v", err)
	}
	account = strings.TrimSpace(string(out))
	return &SDKConfig{account}, nil
}

// Client returns an HTTP client using Google Cloud SDK credentials to
// authorize requests. The token will auto-refresh as necessary. The
// underlying http.RoundTripper will be obtained using the provided
// context. The returned client and its Transport should not be
// modified.
func (c *SDKConfig) Client(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: c,
		},
	}
}

// TokenSource returns an oauth2.TokenSource that retrieve tokens from
// Google Cloud SDK credentials using the provided context.
// It will returns the current access token stored in the credentials,
// and refresh it when it expires, but it won't update the credentials
// with the new access token.
func (c *SDKConfig) TokenSource(ctx context.Context) oauth2.TokenSource {
	return c
}

func parseConfigHelperResp(b []byte) (*oauth2.Token, error) {
	var r configHelperResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parsing the config-helper output: %v", err)
	}
	expiryStr := r.Credential.TokenExpiry
	expiry, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		return nil, fmt.Errorf("parsing the access token expiry time: %v", err)
	}
	return &oauth2.Token{
		AccessToken: r.Credential.AccessToken,
		Expiry:      expiry,
	}, nil
}

// Token returns an oauth2.Token retrieved from the Google Cloud SDK.
func (c *SDKConfig) Token() (*oauth2.Token, error) {
	cmd := exec.Command("gcloud", "config", "config-helper", "--account", c.account, "--format=json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running the config-helper command: %v", err)
	}
	return parseConfigHelperResp(out)
}

func guessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}
