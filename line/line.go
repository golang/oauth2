// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package line provides constants for using OAuth2 to access LINE.
package line // import "golang.org/x/oauth2/line"

import (
	"golang.org/x/oauth2"
)

// Endpoint is LINE's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://access.line.me/oauth2/v2.1/authorize",
	TokenURL: "https://api.line.me/oauth2/v2.1/token",
}
