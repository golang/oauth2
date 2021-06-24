// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package downscope_test

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/downscope"
)

func ExampleNewTokenSource() {
	ctx := context.Background()
	// Initializes an accessBoundary with one Rule.
	accessBoundary := []downscope.AccessBoundaryRule{
		{
			AvailableResource:    "//storage.googleapis.com/projects/_/buckets/foo",
			AvailablePermissions: []string{"inRole:roles/storage.objectViewer"},
		},
	}

	var rootSource oauth2.TokenSource
	// This Source can be initialized in multiple ways; the following example uses
	// Application Default Credentials.

	// rootSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")

	dts, err := downscope.NewTokenSource(ctx, downscope.DownscopingConfig{RootSource: rootSource, Rules: accessBoundary})
	if err != nil {
		_ = dts
	}
	// You can now use the token held in myTokenSource to make
	// Google Cloud Storage calls, as follows:

	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
}
