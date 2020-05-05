// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"fmt"
)

const DefaultState = "state"

// DefaultAuthorizationHandler is a commandline-based auth handler
// that prints the auth URL on the console and prompts the user to
// authorize in the browser and paste the auth code back via stdin.
// When using this auth handler, DefaultState must be used.
func DefaultAuthorizationHandler(authCodeUrl string) (string, string, error) {
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authCodeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, DefaultState, nil
}
