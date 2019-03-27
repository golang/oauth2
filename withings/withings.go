// Copyright 2019 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package withings provides constants for using OAuth2 to access the Withings API.
package withings

import (
	"golang.org/x/oauth2"
)

// Endpoint is Withing's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://account.withings.com/oauth2_user/authorize2",
	TokenURL: "hhttps://account.withings.com/oauth2/token",
}
