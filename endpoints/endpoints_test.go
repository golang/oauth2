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

func TestVaultVisionEndpoint(t *testing.T) {

	var endpointTests = []struct {
		in  string
		out oauth2.Endpoint
	}{
		{
			in: "https://testing.vvkey.io",
			out: oauth2.Endpoint{
				AuthURL:  "https://testing.vvkey.io/authorize",
				TokenURL: "https://testing.vvkey.io/oauth/token",
			},
		},
		{
			in: "https://auth.vaultvision.com",
			out: oauth2.Endpoint{
				AuthURL:  "https://auth.vaultvision.com/authorize",
				TokenURL: "https://auth.vaultvision.com/oauth/token",
			},
		},
	}

	for _, tt := range endpointTests {
		t.Run(tt.in, func(t *testing.T) {
			endpoint := VaultVision(tt.in)
			if endpoint != tt.out {
				t.Errorf("got %q, want %q", endpoint, tt.out)
			}
		})
	}
}
