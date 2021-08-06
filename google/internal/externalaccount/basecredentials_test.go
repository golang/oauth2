// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	textBaseCredPath = "testdata/3pi_cred.txt"
	jsonBaseCredPath = "testdata/3pi_cred.json"
)

var testBaseCredSource = CredentialSource{
	File:   textBaseCredPath,
	Format: format{Type: fileTypeText},
}

var testConfig = Config{
	Audience:         "32555940559.apps.googleusercontent.com",
	SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	TokenInfoURL:     "http://localhost:8080/v1/tokeninfo",
	ClientSecret:     "notsosecret",
	ClientID:         "rbrgnognrhongo3bi4gb9ghg9g",
	CredentialSource: testBaseCredSource,
	Scopes:           []string{"https://www.googleapis.com/auth/devstorage.full_control"},
}

var (
	baseCredsRequestBody        = "audience=32555940559.apps.googleusercontent.com&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.full_control&subject_token=street123&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
	baseCredsResponseBody       = `{"access_token":"Sample.Access.Token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/cloud-platform"}`
	correctAT                   = "Sample.Access.Token"
	expiry                int64 = 234852
)
var (
	testNow = func() time.Time { return time.Unix(expiry, 0) }
)

func TestToken(t *testing.T) {

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/"; got != want {
			t.Errorf("URL.String(): got %v but want %v", got, want)
		}
		headerAuth := r.Header.Get("Authorization")
		if got, want := headerAuth, "Basic cmJyZ25vZ25yaG9uZ28zYmk0Z2I5Z2hnOWc6bm90c29zZWNyZXQ="; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, "application/x-www-form-urlencoded"; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed reading request body: %s.", err)
		}
		if got, want := string(body), baseCredsRequestBody; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(baseCredsResponseBody))
	}))
	defer targetServer.Close()

	testConfig.TokenURL = targetServer.URL
	ourTS := tokenSource{
		ctx:  context.Background(),
		conf: &testConfig,
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = testNow

	tok, err := ourTS.Token()
	if err != nil {
		t.Fatalf("Unexpected error: %e", err)
	}
	if got, want := tok.AccessToken, correctAT; got != want {
		t.Errorf("Unexpected access token: got %v, but wanted %v", got, want)
	}
	if got, want := tok.TokenType, "Bearer"; got != want {
		t.Errorf("Unexpected TokenType: got %v, but wanted %v", got, want)
	}

	if got, want := tok.Expiry, now().Add(time.Duration(3600)*time.Second); got != want {
		t.Errorf("Unexpected Expiry: got %v, but wanted %v", got, want)
	}

}

func TestValidateURL(t *testing.T) {
	var urlValidityTests = []struct {
		input   string
		pattern []string
		result  bool
	}{
		{"https://sts.googleapis.com", validTokenURLPatterns, true},
		{"https://.sts.google.com", validTokenURLPatterns, false},
		{"https://badsts.googleapis.com", validTokenURLPatterns, false},
		{"https://sts.asfeasfesef.googleapis.com", validTokenURLPatterns, true},
		{"https://sts.asfe.asfesef.googleapis.com", validTokenURLPatterns, false},
		{"https://sts..googleapis.com", validTokenURLPatterns, false},
		{"https://-sts.googleapis.com", validTokenURLPatterns, false},
		{"https://us-east-1-sts.googleapis.com", validTokenURLPatterns, true},
		{"https://us-ea.st-1-sts.googleapis.com", validTokenURLPatterns, false},
		// Repeat for iamcredentials as well
		{"https://iamcredentials.googleapis.com", validImpersonateURLPatterns, true},
		{"https://.iamcredentials.googleapis.com", validImpersonateURLPatterns, false},
		{"https://badiamcredentials.googleapis.com", validImpersonateURLPatterns, false},
		{"https://iamcredentials.asfeasfesef.googleapis.com", validImpersonateURLPatterns, true},
		{"https://iamcredentials.asfe.asfesef.googleapis.com", validImpersonateURLPatterns, false},
		{"https://iamcredentials..googleapis.com", validImpersonateURLPatterns, false},
		{"https://-iamcredentials.googleapis.com", validImpersonateURLPatterns, false},
		{"https://us-east-1-iamcredentials.googleapis.com", validImpersonateURLPatterns, true},
		{"https://us-ea.st-1-iamcredentials.googleapis.com", validImpersonateURLPatterns, false},
	}
	for _, tt := range urlValidityTests {
		t.Run(" "+tt.input, func(t *testing.T) { // We prepend a space ahead of the test input when outputting for sake of readability.
			valid, err := validateURL(tt.input, tt.pattern)
			if err != nil {
				t.Errorf("validateURL returned an error: %v", err)
				return
			}
			if valid != tt.result {
				t.Errorf("got %v, want %v", valid, tt.result)
			}
		})
	}
}
