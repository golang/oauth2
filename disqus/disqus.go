// Copyright 2017 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package disqus provides constants for using OAuth2 to access Disqus.
package disqus

import (
	"golang.org/x/oauth2"
)

// Endpoint is Disqus's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://disqus.com/api/oauth/2.0/authorize",
	TokenURL: "https://disqus.com/api/oauth/2.0/access_token",
}
