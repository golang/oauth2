// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var testImpersonateConfig = Config{
	Audience:         "32555940559.apps.googleusercontent.com",
	SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	TokenInfoURL:     "http://localhost:8080/v1/tokeninfo",
	ClientSecret:     "notsosecret",
	ClientID:         "rbrgnognrhongo3bi4gb9ghg9g",
	CredentialSource: testBaseCredSource,
	Scopes:           []string{"https://www.googleapis.com/auth/devstorage.full_control"},
}

var (
	baseImpersonateCredsReqBody  = "audience=32555940559.apps.googleusercontent.com&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&options=null&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&subject_token=street123&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
	baseImpersonateCredsRespBody = `{"accessToken":"Second.Access.Token","expireTime":"2020-12-28T15:01:23Z"}`
)

func TestImpersonation(t *testing.T) {
	impersonateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/"; got != want {
			t.Errorf("URL.String(): got %v but want %v", got, want)
		}
		headerAuth := r.Header.Get("Authorization")
		if got, want := headerAuth, "Bearer Sample.Access.Token"; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, "application/json"; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed reading request body: %v.", err)
		}
		if got, want := string(body), "{\"lifetime\":\"3600s\",\"scope\":[\"https://www.googleapis.com/auth/devstorage.full_control\"]}"; got != want {
			t.Errorf("Unexpected impersonation payload: got %v but want %v", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(baseImpersonateCredsRespBody))
	}))
	testImpersonateConfig.ServiceAccountImpersonationURL = impersonateServer.URL
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
			t.Fatalf("Failed reading request body: %v.", err)
		}
		if got, want := string(body), baseImpersonateCredsReqBody; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(baseCredsResponseBody))
	}))
	defer targetServer.Close()

	testImpersonateConfig.TokenURL = targetServer.URL
	ourTS := testImpersonateConfig.TokenSource(context.Background())

	oldNow := now
	defer func() { now = oldNow }()
	now = testNow

	tok, err := ourTS.Token()
	if err != nil {
		t.Fatalf("Unexpected error: %e", err)
	}
	if got, want := tok.AccessToken, "Second.Access.Token"; got != want {
		t.Errorf("Unexpected access token: got %v, but wanted %v", got, want)
	}
	if got, want := tok.TokenType, "Bearer"; got != want {
		t.Errorf("Unexpected TokenType: got %v, but wanted %v", got, want)
	}
}
