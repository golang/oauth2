// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vk provides constants for using OAuth2 to access VK.ru.
package vk // import "golang.org/x/oauth2/vk"

import (
	"golang.org/x/oauth2"
)

// Endpoint is VK's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://oauth.vk.ru/authorize",
	TokenURL: "https://oauth.vk.ru/access_token",
}
