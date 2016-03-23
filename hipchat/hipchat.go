// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hipchat provides constants for using OAuth2 to access HipChat.
package hipchat // import "golang.org/x/oauth2/hipchat"

import (
	"golang.org/x/oauth2"
)

// Endpoint is HipChat's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://www.hipchat.com/users/authorize",
	TokenURL: "https://api.hipchat.com/v2/oauth/token",
}
