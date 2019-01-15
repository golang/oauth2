// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package snapchat provides constants for using OAuth2 to access Snapchat.
package snapchat // import "golang.org/x/oauth2/snapchat"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Snapchat's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.snapchat.com/login/oauth2/authorize",
	TokenURL: "https://accounts.snapchat.com/login/oauth2/access_token",
}
