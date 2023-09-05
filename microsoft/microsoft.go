// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package microsoft provides constants for using OAuth2 to access Windows Live ID.
package microsoft // import "golang.org/x/oauth2/microsoft"

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// LiveConnectEndpoint is Windows's Live ID OAuth 2.0 endpoint.
var LiveConnectEndpoint = endpoints.Microsoft

// AzureADEndpoint returns a new oauth2.Endpoint for the given tenant at Azure Active Directory.
// If tenant is empty, it uses the tenant called `common`.
//
// For more information see:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
func AzureADEndpoint(tenant string) oauth2.Endpoint {
	return endpoints.AzureAD(tenant)
}
