// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"testing"
)

var jwtJSONKeyUniverseDomain = []byte(`{
  "type": "service_account",
  "project_id": "fake_project",
  "universe_domain": "example.com",
  "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
  "private_key": "super secret key",
  "client_email": "gopher@developer.gserviceaccount.com",
  "client_id": "gopher.apps.googleusercontent.com",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gopher%40fake_project.iam.gserviceaccount.com"
}`)

func TestCredentialsFromJSONWithParams_UniverseDomain(t *testing.T) {
	ctx := context.Background()
	scope := "https://www.googleapis.com/auth/cloud-platform"
	params := CredentialsParams{
		Scopes: []string{scope},
	}
	creds, err := CredentialsFromJSONWithParams(ctx, jwtJSONKeyUniverseDomain, params)
	if err != nil {
		t.Fatal(err)
	}

	if want := "fake_project"; creds.ProjectID != want {
		t.Fatalf("got %q, want %q", creds.ProjectID, want)
	}
	if want := "example.com"; creds.UniverseDomain() != want {
		t.Fatalf("got %q, want %q", creds.UniverseDomain(), want)
	}
}
