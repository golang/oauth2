// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"fmt"

	"github.com/google/uuid"
)

// RandomAuthorizationState generates a state via UUID generator.
func RandomAuthorizationState() string {
	return uuid.New().String()
}

// DefaultAuthorizationHandler returns a command line auth handler
// that prints the auth URL on the console and prompts the user to
// authorize in the browser and paste the auth code back via stdin.
//
// For convenience, this handler returns a pre-configured state
// instead of asking the user to additionally paste the state from
// the auth response. In order for this to work, the state
// configured here should match the one in the oauth2 AuthTokenURL.
func DefaultAuthorizationHandler(state string) AuthorizationHandler {
	return func(authCodeURL string) (string, string, error) {
		return defaultAuthorizationHandlerHelper(state, authCodeURL)
	}
}

func defaultAuthorizationHandlerHelper(state string, authCodeURL string) (string, string, error) {
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authCodeURL)
	fmt.Println("Enter authorization code: ")
	var code string
	fmt.Scanln(&code)
	return code, state, nil
}
