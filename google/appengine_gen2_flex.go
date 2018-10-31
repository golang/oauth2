// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !appengine

// This file applies to App Engine second generation runtimes (>= Go 1.11) and App Engine flexible.

package google

import (
	"log"
	"sync"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	once sync.Once

	logFunc = func() {
		log.Print("google: AppEngineTokenSource is deprecated on App Engine standard second generation runtimes (>= Go 1.11) and App Engine flexible. Please use DefaultTokenSource or ComputeTokenSource.")
	}
)

// See comment on AppEngineTokenSource in appengine.go.
func appEngineTokenSource(ctx context.Context, scope ...string) oauth2.TokenSource {
	once.Do(logFunc)
	return ComputeTokenSource("")
}
