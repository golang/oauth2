// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package lyft provides constants for using OAuth2 to access Lyft.
package lyft // import "golang.org/x/oauth2/lyft"

import (
  "golang.org/x/oauth2"
)

// Endpoint is Lyft's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
  AuthURL:  "https://api.lyft.com/oauth/authorize",
  TokenURL: "https://api.lyft.com/oauth/token",
}
