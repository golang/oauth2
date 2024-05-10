// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asgardeo provides constants for using OAuth2 to access Asgardeo.
package asgardeo // import "golang.org/x/oauth2/asgardeo"

import (
	"golang.org/x/oauth2"
)

// Asgardeo returns a new oauth2.Endpoint for the given tenant.
func AsgardeoEndpoint(tenant string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  "https://api.asgardeo.io/t/" + tenant + "/oauth2/authorize",
		TokenURL: "https://api.asgardeo.io/t/" + tenant + "/oauth2/token",
	}
}
