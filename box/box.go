// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package box provides constants for using OAuth2 to access box.com.
package box // import "golang.org/x/oauth2/box"

import (
	"golang.org/x/oauth2"
)

// Endpoint is box.com's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://account.box.com/api/oauth2/authorize",
	TokenURL: "https://api.box.com/oauth2/token",
}
