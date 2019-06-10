// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apple provides constants for using OAuth2 to access Kakao.
package apple // import "golang.org/x/oauth2/apple"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Apple's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}
