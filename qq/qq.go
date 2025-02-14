// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package qq provides constants for using OAuth2 to access qq.
package qq // import "golang.org/x/oauth2/qq"

import (
	"golang.org/x/oauth2"
)

// Endpoint is QQ's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://graph.qq.com/oauth2.0/authorize",
	TokenURL:  "https://graph.qq.com/oauth2.0/token",
}
