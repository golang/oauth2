// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"os"
	"testing"
)

var testMemoryConfig = Config{
	Audience:                       "32555940559.apps.googleusercontent.com",
	SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
	TokenURL:                       "http://localhost:8080/v1/token",
	TokenInfoURL:                   "http://localhost:8080/v1/tokeninfo",
	ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-gcs-admin@$PROJECT_ID.iam.gserviceaccount.com:generateAccessToken",
	ClientSecret:                   "notsosecret",
	ClientID:                       "rbrgnognrhongo3bi4gb9ghg9g",
}

func TestRetrieveMemorySubjectToken(t *testing.T) {
	textBaseCred, err := os.ReadFile(textBaseCredPath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", textBaseCredPath, err)
	}

	jsonBaseCred, err := os.ReadFile(jsonBaseCredPath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", jsonBaseCredPath, err)
	}

	var memorySourceTests = []struct {
		name string
		cs   CredentialSource
		want string
	}{
		{
			name: "UntypedMemorySource",
			cs: CredentialSource{
				Memory: textBaseCred,
			},
			want: "street123",
		},
		{
			name: "TextMemorySource",
			cs: CredentialSource{
				Memory: textBaseCred,
				Format: Format{Type: fileTypeText},
			},
			want: "street123",
		},
		{
			name: "JSONMemorySource",
			cs: CredentialSource{
				Memory: jsonBaseCred,
				Format: Format{Type: fileTypeJSON, SubjectTokenFieldName: "SubjToken"},
			},
			want: "321road",
		},
	}

	for _, test := range memorySourceTests {
		test := test
		tfc := testMemoryConfig
		tfc.CredentialSource = &test.cs

		t.Run(test.name, func(t *testing.T) {
			base, err := tfc.parse(context.Background())
			if err != nil {
				t.Fatalf("parse() failed %v", err)
			}

			out, err := base.subjectToken()
			if err != nil {
				t.Errorf("Method subjectToken() errored.")
			} else if test.want != out {
				t.Errorf("got %v but want %v", out, test.want)
			}

			if got, want := base.credentialSourceType(), "memory"; got != want {
				t.Errorf("got %v but want %v", got, want)
			}
		})
	}
}
