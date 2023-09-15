// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package patreon provides constants for using OAuth2 to access Patreon APIs.
package patreon // import "golang.org/x/oauth2/patreon"

import (
	"golang.org/x/oauth2"
)

// Endpoint is the Patreon OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://www.patreon.com/oauth2/authorize",
	TokenURL: "https://www.patreon.com/api/oauth2/token",
}
