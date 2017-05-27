// Copyright 2015 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package yahoo provides constants for using OAuth2 to access Yahoo.
package yahoo // import "golang.org/x/oauth2/yahoo"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Yahoo's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://api.login.yahoo.com/oauth/v2/request_auth",
	TokenURL: "https://api.login.yahoo.com/oauth/v2/get_token",
}
