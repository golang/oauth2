// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestValidateURLTokenURL(t *testing.T) {
	var urlValidityTests = []struct {
		tokURL        string
		expectSuccess bool
	}{
		{"https://east.sts.googleapis.com", true},
		{"https://sts.googleapis.com", true},
		{"https://sts.asfeasfesef.googleapis.com", true},
		{"https://us-east-1-sts.googleapis.com", true},
		{"https://sts.googleapis.com/your/path/here", true},
		{"https://.sts.googleapis.com", false},
		{"https://badsts.googleapis.com", false},
		{"https://sts.asfe.asfesef.googleapis.com", false},
		{"https://sts..googleapis.com", false},
		{"https://-sts.googleapis.com", false},
		{"https://us-ea.st-1-sts.googleapis.com", false},
		{"https://sts.googleapis.com.evil.com/whatever/path", false},
		{"https://us-eas\\t-1.sts.googleapis.com", false},
		{"https:/us-ea/st-1.sts.googleapis.com", false},
		{"https:/us-east 1.sts.googleapis.com", false},
		{"https://", false},
		{"http://us-east-1.sts.googleapis.com", false},
		{"https://us-east-1.sts.googleapis.comevil.com", false},
	}
	ctx := context.Background()
	for _, tt := range urlValidityTests {
		t.Run(" "+tt.tokURL, func(t *testing.T) { // We prepend a space ahead of the test input when outputting for sake of readability.
			config := testConfig
			config.TokenURL = tt.tokURL
			_, err := config.TokenSource(ctx)

			if tt.expectSuccess && err != nil {
				t.Errorf("got %v but want nil", err)
			} else if !tt.expectSuccess && err == nil {
				t.Errorf("got nil but expected an error")
			}
		})
	}
	for _, el := range urlValidityTests {
		el.tokURL = strings.ToUpper(el.tokURL)
	}
	for _, tt := range urlValidityTests {
		t.Run(" "+tt.tokURL, func(t *testing.T) { // We prepend a space ahead of the test input when outputting for sake of readability.
			config := testConfig
			config.TokenURL = tt.tokURL
			_, err := config.TokenSource(ctx)

			if tt.expectSuccess && err != nil {
				t.Errorf("got %v but want nil", err)
			} else if !tt.expectSuccess && err == nil {
				t.Errorf("got nil but expected an error")
			}
		})
	}
}

func TestValidateURLImpersonateURL(t *testing.T) {
	var urlValidityTests = []struct {
		impURL        string
		expectSuccess bool
	}{
		{"https://east.iamcredentials.googleapis.com", true},
		{"https://iamcredentials.googleapis.com", true},
		{"https://iamcredentials.asfeasfesef.googleapis.com", true},
		{"https://us-east-1-iamcredentials.googleapis.com", true},
		{"https://iamcredentials.googleapis.com/your/path/here", true},
		{"https://.iamcredentials.googleapis.com", false},
		{"https://badiamcredentials.googleapis.com", false},
		{"https://iamcredentials.asfe.asfesef.googleapis.com", false},
		{"https://iamcredentials..googleapis.com", false},
		{"https://-iamcredentials.googleapis.com", false},
		{"https://us-ea.st-1-iamcredentials.googleapis.com", false},
		{"https://iamcredentials.googleapis.com.evil.com/whatever/path", false},
		{"https://us-eas\\t-1.iamcredentials.googleapis.com", false},
		{"https:/us-ea/st-1.iamcredentials.googleapis.com", false},
		{"https:/us-east 1.iamcredentials.googleapis.com", false},
		{"https://", false},
		{"http://us-east-1.iamcredentials.googleapis.com", false},
		{"https://us-east-1.iamcredentials.googleapis.comevil.com", false},
	}
	ctx := context.Background()
	for _, tt := range urlValidityTests {
		t.Run(" "+tt.impURL, func(t *testing.T) { // We prepend a space ahead of the test input when outputting for sake of readability.
			config := testConfig
			config.TokenURL = "https://sts.googleapis.com" // Setting the most basic acceptable tokenURL
			config.ServiceAccountImpersonationURL = tt.impURL
			_, err := config.TokenSource(ctx)

			if tt.expectSuccess && err != nil {
				t.Errorf("got %v but want nil", err)
			} else if !tt.expectSuccess && err == nil {
				t.Errorf("got nil but expected an error")
			}
		})
	}
	for _, el := range urlValidityTests {
		el.impURL = strings.ToUpper(el.impURL)
	}
	for _, tt := range urlValidityTests {
		t.Run(" "+tt.impURL, func(t *testing.T) { // We prepend a space ahead of the test input when outputting for sake of readability.
			config := testConfig
			config.TokenURL = "https://sts.googleapis.com" // Setting the most basic acceptable tokenURL
			config.ServiceAccountImpersonationURL = tt.impURL
			_, err := config.TokenSource(ctx)

			if tt.expectSuccess && err != nil {
				t.Errorf("got %v but want nil", err)
			} else if !tt.expectSuccess && err == nil {
				t.Errorf("got nil but expected an error")
			}
		})
	}
}
