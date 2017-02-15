// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

func ExampleConfig() {
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/o/oauth2/auth",
			TokenURL: "https://provider.com/o/oauth2/token",
		},
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token. The HTTP Client returned by
	// conf.Client will refresh the token as necessary.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	client := conf.Client(ctx, tok)
	client.Get("...")
}

func ExampleNewClient() {
	customHTTPClient := &http.Client{
		Timeout: time.Duration(10) * time.Seconds,
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, customHTTPClient)

	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://provider.com/o/oauth2/token",
		},
	}

	// Use only if there is a high degree of trust between
	// the resource owner and the client.
	tokenSrc, err := conf.PasswordCredentialsToken(ctx, "YOUR_USERNAME", "YOUR_PASSWORD")
	if err != nil {
		log.Fatal(err)
	}

	// The Timeout configuration on the HTTP Client
	// constructed above is used only during token
	// acquisition and is not configured as part of
	// the client returned from NewClient.
	authedHTTPClient := oauth2.NewClient(ctx, tokenSrc)

	response, err := authedHTTPClient.Get("http://www.example.com")
	if err != nil {
		log.Fatal(err)
	}

	if response.Code != http.StatusOK {
		log.Fatal("response was not 200")
	}
}
