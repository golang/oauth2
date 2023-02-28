// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package paypal provides constants for using OAuth2 to access PayPal.
package paypal // import "golang.org/x/oauth2/paypal"

import (
	"golang.org/x/oauth2/endpoints"
)

// Endpoint is PayPal's OAuth 2.0 endpoint in live (production) environment.
var Endpoint = endpoints.PayPal

// SandboxEndpoint is PayPal's OAuth 2.0 endpoint in sandbox (testing) environment.
var SandboxEndpoint = endpoints.PayPalSandbox
