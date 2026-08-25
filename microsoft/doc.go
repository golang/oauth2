// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package microsoft provides support for making OAuth2 authorized and authenticated
// HTTP requests to Microsoft APIs. It supports the client credentials flow using
// client certificates to sign a JWT assertion. For the client credentials flow using
// a shared secret, use the clientcredentials package.
//
// For more information on the client credentials flow using certificates, see
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
//
// Usage
//
// To generate a client assertion, both the private key and certificate are required. The token is signed
// using the key, but the service requires the SHA-1 hash of the certificate in order to identify the key
// being used.
//
// Scopes requested should be in the form https://api.endpoint/.default, for example
// https://graph.microsoft.com/.default
//
// The token URL for an Azure Active Directory tenant can be obtained with the AzureADEndpoint function.
//
package microsoft // import "golang.org/x/oauth2/microsoft"
