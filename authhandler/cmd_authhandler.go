// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package authhandler

import (
	"fmt"
)

// CmdAuthorizationHandler returns a command line auth handler
// that prints the auth URL on the console and prompts the user to
// authorize in the browser and paste the auth code back via stdin.
//
// Per OAuth protocol, a unique "state" string should be sent and verified
// before exchanging auth code for OAuth token to prevent CSRF attacks.
//
// For convenience, this handler returns a pre-configured state
// instead of asking the user to additionally paste the state from
// the auth response. In order for this to work, the state
// configured here must match the state used in authCodeURL.
func CmdAuthorizationHandler(state string) AuthorizationHandler {
	return func(authCodeURL string) (string, string, error) {
		fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authCodeURL)
		fmt.Println("Enter authorization code:")
		var code string
		fmt.Scanln(&code)
		return code, state, nil
	}
}
