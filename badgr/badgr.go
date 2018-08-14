// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package badgr provides constants for using OAuth2 to access badgr.
package badgr // import "golang.org/x/oauth2/badgr"

import (
	"golang.org/x/oauth2"
)

// Endpoint is badgr's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://badgr.io/auth/oauth2/authorize",
	TokenURL: "https://api.badgr.io/o/token",
}
