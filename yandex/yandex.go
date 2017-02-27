// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package yandex provides constants for using OAuth2 to access Yandex API.
package yandex // import "golang.org/x/oauth2/yandex"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Yandex OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://oauth.yandex.com/authorize",
	TokenURL: "https://oauth.yandex.com/token",
}
