// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package github provides constants for using OAuth2 to access Twitter.
package twitter // import "golang.org/x/oauth2/twitter"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Twitter's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://api.twitter.com/oauth/authorize",
	TokenURL: "https://api.twitter.com/oauth/access_token",
}
