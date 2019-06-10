// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package endpoints provides constants for using OAuth2 to access different
// 3rd-party services.
package endpoints // import "golang.org/x/oauth2/endpoints"

import (
	"golang.org/x/oauth2"
)

// AppleSignIn is Apple's OAuth 2.0 endpoint for “Sign-in with Apple”.
//
// Source: https://developer.apple.com/sign-in-with-apple/
var AppleSignIn = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}
