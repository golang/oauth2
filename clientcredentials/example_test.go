// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientcredentials_test

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

func ExampleConfig() {
	ctx := context.Background()
	conf := &clientcredentials.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		TokenURL:     "https://provider.com/o/oauth2/token",
	}

	// For the clientcredentials flow simply get a client from
	// the Config directly.
	client := conf.Client(ctx)
	client.Get("...")
}
