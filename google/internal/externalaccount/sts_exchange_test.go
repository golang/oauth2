// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var auth = ClientAuthentication{
	AuthStyle:    oauth2.AuthStyleInHeader,
	ClientID:     clientID,
	ClientSecret: clientSecret,
}

var tokenRequest = STSTokenExchangeRequest{
	ActingParty: struct {
		ActorToken     string
		ActorTokenType string
	}{},
	GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
	Resource:           "",
	Audience:           "32555940559.apps.googleusercontent.com", //TODO: Make sure audience is correct in this test (might be mismatched)
	Scope:              []string{"https://www.googleapis.com/auth/devstorage.full_control"},
	RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	SubjectToken:       "Sample.Subject.Token",
	SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
}

var requestbody = "audience=32555940559.apps.googleusercontent.com&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.full_control&subject_token=Sample.Subject.Token&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
var responseBody = `{"access_token":"Sample.Access.Token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/cloud-platform"}`
var expectedToken = STSTokenExchangeResponse{
	AccessToken:     "Sample.Access.Token",
	IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	TokenType:       "Bearer",
	ExpiresIn:       3600,
	Scope:           "https://www.googleapis.com/auth/cloud-platform",
	RefreshToken:    "",
}

func TestExchangeToken(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic cmJyZ25vZ25yaG9uZ28zYmk0Z2I5Z2hnOWc6bm90c29zZWNyZXQ=" {
			t.Errorf("Unexpected autohrization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != requestbody {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(responseBody))
	}))

	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	resp, err := ExchangeToken(context.Background(), ts.URL, &tokenRequest, auth, headers, nil)
	if err != nil {
		t.Errorf("ExchangeToken failed with error: %s", err)
	}

	if diff := cmp.Diff(expectedToken, *resp); diff != "" {
		t.Errorf("mismatched messages received by mock server (-want +got): \n%v", diff)
	}

}

func TestExchangeToken_Err(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("what's wrong with this response?"))
	}))

	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	_, err := ExchangeToken(context.Background(), ts.URL, &tokenRequest, auth, headers, nil)
	if err == nil {
		t.Errorf("Expected handled error; instead got nil.")
	}
}