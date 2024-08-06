// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package endpoints

import (
	"testing"

	"golang.org/x/oauth2"
)

func TestAWSCognitoEndpoint(t *testing.T) {

	var endpointTests = []struct {
		in  string
		out oauth2.Endpoint
	}{
		{
			in: "https://testing.auth.us-east-1.amazoncognito.com",
			out: oauth2.Endpoint{
				AuthURL:  "https://testing.auth.us-east-1.amazoncognito.com/oauth2/authorize",
				TokenURL: "https://testing.auth.us-east-1.amazoncognito.com/oauth2/token",
			},
		},
		{
			in: "https://testing.auth.us-east-1.amazoncognito.com/",
			out: oauth2.Endpoint{
				AuthURL:  "https://testing.auth.us-east-1.amazoncognito.com/oauth2/authorize",
				TokenURL: "https://testing.auth.us-east-1.amazoncognito.com/oauth2/token",
			},
		},
	}

	for _, tt := range endpointTests {
		t.Run(tt.in, func(t *testing.T) {
			endpoint := AWSCognito(tt.in)
			if endpoint != tt.out {
				t.Errorf("got %q, want %q", endpoint, tt.out)
			}
		})
	}
}

func TestAuthentikProviderEndpoint(t *testing.T) {

	var endpointTests = []struct {
		Name       string
		userHost   string
		serverHost string
		out        oauth2.Endpoint
	}{
		{
			Name:       "Without Ending URL-Slash",
			userHost:   "https://example.com",
			serverHost: "https://authentik:9000",
			out: oauth2.Endpoint{
				AuthURL:  "https://example.com/application/o/authorize/",
				TokenURL: "https://authentik:9000/application/o/token/",
			},
		},
		{
			Name:       "With Ending URL-Slash",
			userHost:   "https://example.com/",
			serverHost: "https://authentik:9000/",
			out: oauth2.Endpoint{
				AuthURL:  "https://example.com/application/o/authorize/",
				TokenURL: "https://authentik:9000/application/o/token/",
			},
		},
	}

	for _, tt := range endpointTests {
		t.Run(tt.Name, func(t *testing.T) {
			endpoint := AuthentikProvider(tt.userHost, tt.serverHost)
			if endpoint != tt.out {
				t.Errorf("got %q, want %q", endpoint, tt.out)
			}
		})
	}
}
