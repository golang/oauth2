// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mailchimp provides constants for using OAuth2 to access MailChimp.
package mailchimp // import "golang.org/x/oauth2/mailchimp"

import (
	"golang.org/x/oauth2/endpoints"
)

// Endpoint is MailChimp's OAuth 2.0 endpoint.
// See http://developer.mailchimp.com/documentation/mailchimp/guides/how-to-use-oauth2/
var Endpoint = endpoints.Mailchimp
