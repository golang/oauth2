// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package douyu provides constants for using OAuth2 to access Kakao.
package douyu // import "golang.org/x/oauth2/douyu"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Douyu's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://passport.douyu.com/auth/oauth2/authorize",
	TokenURL: "https://passport.douyu.com/auth/oauth2/access_token",
}
