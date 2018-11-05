// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dropbox provides constants for using OAuth2 to access Dropbox.
package dropbox // import "golang.org/x/oauth2/dropbox"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Dropbox's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://www.dropbox.com/oauth2/authorize",
	TokenURL: "https://api.dropboxapi.com/oauth2/token",
}
