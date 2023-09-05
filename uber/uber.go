// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package uber provides constants for using OAuth2 to access Uber.
package uber // import "golang.org/x/oauth2/uber"

import (
	"golang.org/x/oauth2/endpoints"
)

// Endpoint is Uber's OAuth 2.0 endpoint.
var Endpoint = endpoints.Uber
