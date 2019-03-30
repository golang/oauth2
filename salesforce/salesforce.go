// Copyright 2017 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package Salesforce provides constants for using OAuth2 to access Salesforce.
package salesforce

import (
	"golang.org/x/oauth2"
)

// Endpoint is Salesforce OAuth 2.0 endpoint in live (production) environment..
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
	TokenURL: "https://login.salesforce.com/services/oauth2/token",
}

// SandboxEndpoint is Salesforce OAuth 2.0 endpoint in sandbox (testing) environment.
var SandboxEndpoint = oauth2.Endpoint{
	AuthURL:  "https://test.salesforce.com/services/oauth2/authorize",
	TokenURL: "https://test.salesforce.com/services/oauth2/token",
}
