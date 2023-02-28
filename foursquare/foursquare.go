// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package foursquare provides constants for using OAuth2 to access Foursquare.
package foursquare // import "golang.org/x/oauth2/foursquare"

import (
	"golang.org/x/oauth2/endpoints"
)

// Endpoint is Foursquare's OAuth 2.0 endpoint.
var Endpoint = endpoints.Foursquare
