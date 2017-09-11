// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package baidu provides constants for using OAuth2 to access Baidu.
package baidu // import "golang.org/x/oauth2/baidu"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Baidu's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "http://openapi.baidu.com/oauth/2.0/authorize",
	TokenURL: "https://openapi.baidu.com/oauth/2.0/token",
}
