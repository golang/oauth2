// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package downscope

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

var (
	standardReqBody  = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&options=%257B%2522accessBoundary%2522%253A%257B%2522accessBoundaryRules%2522%253A%255B%257B%2522availableResource%2522%253A%2522test1%2522%252C%2522availablePermissions%2522%253A%255B%2522Perm1%252C%2Bperm2%2522%255D%257D%255D%257D%257D&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=Mellon&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
	standardRespBody = `{"access_token":"Open Sesame","expires_in":432,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`
)

func Test_DownscopedTokenSource(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Unexpected request method, %v is found", r.Method)
		}
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found", r.URL)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		if got, want := string(body), standardReqBody; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v,", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(standardRespBody))

	}))
	new := []AccessBoundaryRule{
		AccessBoundaryRule{
			AvailableResource:    "test1",
			AvailablePermissions: []string{"Perm1", "Perm2"},
		},
	}
	myTok := oauth2.Token{AccessToken: "Mellon"}
	tmpSrc := oauth2.StaticTokenSource(&myTok)
	out, err := downscopedTokenWithEndpoint(context.Background(), DownscopingConfig{tmpSrc, new}, ts.URL)
	if err != nil {
		t.Fatalf("NewDownscopedTokenSource failed with error: %v", err)
	}
	_, err = out.Token()
	if err != nil {
		t.Fatalf("Token() call failed with error %v", err)
	}
}

func ExampleNewTokenSource() {
	ctx := context.Background()
	// Initializes an accessBoundary with one Rule
	accessBoundary := []AccessBoundaryRule{
		AccessBoundaryRule{
			AvailableResource:    "//storage.googleapis.com/projects/_/buckets/foo",
			AvailablePermissions: []string{"inRole:roles/storage.objectViewer"},
		},
	}

	var rootSource oauth2.TokenSource
	// This Source can be initialized using Application Default Credentials as follows:

	// rootSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")

	myTokenSource, err := NewTokenSource(ctx, DownscopingConfig{RootSource: rootSource, Rules: accessBoundary})
	//myTokenSource, err := NewSource(rootSource, myBoundary)
	if err != nil {
		log.Fatalf("failed to generate downscoped token source: %v", err)
	}
	_ = myTokenSource
	// You can now use the token held in myTokenSource to make
	// Google Cloud Storage calls, as follows:

	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
}

type localTokenSource struct {
	tokenBrokerURL       string
	tokenSourceForBroker oauth2.TokenSource
}

func (lts localTokenSource) Token() (*oauth2.Token, error) {
	// Make a call to a remote token broker, which runs downscope.NewTokenSource
	// to generate a downscoped version of a token it holds.  Return
	var tok oauth2.Token
	return &tok, nil
}

// ExampleRefreshableToken provices a sample of how a token consumer would
// construct a refreshable token by wrapping a method that requests a
// downscoped token from a token broker in an oauth2.ReuseTokenSource
func ExampleRefreshableToken() {
	var myCredentials oauth2.TokenSource
	// This Source contains the credentials that the token consumer uses to
	// authenticate itself to the token broker from which it is requesting
	// a downscoped token.
	myTokenSource := localTokenSource{
		tokenBrokerURL:       "www.foo.bar",
		tokenSourceForBroker: myCredentials,
	}

	downscopedToken := oauth2.ReuseTokenSource(nil, myTokenSource)
	// downscopedToken can now be used as a refreshable token for Google Cloud Storage calls
	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
	_ = downscopedToken
}
