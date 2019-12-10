// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package aws provides constants for using OAuth2 to access aws services.
package aws // import "golang.org/x/oauth2/aws"

import (
	"golang.org/x/oauth2"
)

// CognitoEndpoint returns a new oauth2.Endpoint for the supplied Cognito domain which is
// linked to your Cognito User Pool.
//
// Example domain: https://testing.auth.us-east-1.amazoncognito.com
//
// For more information see:
// https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html
// https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html
func CognitoEndpoint(domain string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  domain + "/oauth2/authorize",
		TokenURL: domain + "/oauth2/token",
	}
}
