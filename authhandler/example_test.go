// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package authhandler_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
)

func ExampleCmdAuthorizationHandler() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
				"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
				"scope": "pubsub",
				"token_type": "bearer",
				"expires_in": 3600
			}`))
	}))
	defer ts.Close()

	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID: "testClientID",
		Scopes:   []string{"pubsub"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "testAuthCodeURL",
			TokenURL: ts.URL,
		},
	}
	state := "unique_state"

	token, err := authhandler.TokenSource(ctx, conf, state, authhandler.CmdAuthorizationHandler(state)).Token()

	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("AccessToken: %s", token.AccessToken)

	// Output:
	// Go to the following link in your browser:
	//
	//    testAuthCodeURL?client_id=testClientID&response_type=code&scope=pubsub&state=unique_state
	//
	// Enter authorization code:
	// AccessToken: 90d64460d14870c08c81352a05dedd3465940a7c
}
