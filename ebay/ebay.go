// Copyright 2017 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ebay provides constants for using OAuth2 to access Amazon.
package ebay

import (
	"golang.org/x/oauth2"
)

// Endpoint is Ebay's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://auth.ebay.com/oauth2/authorize",
	TokenURL: "https://api.ebay.com/identity/v1/oauth2/token",
}
