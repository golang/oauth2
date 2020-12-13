// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package microsoft_test

import (
	"context"

	"golang.org/x/oauth2/microsoft"
)

func ExampleClientCertificate() {
	ctx := context.Background()

	conf := microsoft.Config{
		ClientID:    "YOUR_CLIENT_ID",
		PrivateKey:  []byte("YOUR_ENCODED_PRIVATE_KEY"),
		Certificate: []byte("YOUR_ENCODED_CERTIFICATE"),
		Scopes:      []string{"https://graph.microsoft.com/.default"},
		TokenURL:    microsoft.AzureADEndpoint("YOUR_TENANT_ID").TokenURL,
	}

	client := conf.Client(ctx)
	client.Get("https://graph.microsoft.com/v1.0/me")
}
