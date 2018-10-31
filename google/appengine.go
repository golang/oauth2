// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"time"

	"golang.org/x/net/context"
)

// Set at init time by appengine_gen1.go. If nil, we're not on App Engine standard first generation (<= Go 1.9) or App Engine flexible.
var appengineTokenFunc func(c context.Context, scopes ...string) (token string, expiry time.Time, err error)

// Set at init time by appengine_gen1.go. If nil, we're not on App Engine standard first generation (<= Go 1.9) or App Engine flexible.
var appengineAppIDFunc func(c context.Context) string
