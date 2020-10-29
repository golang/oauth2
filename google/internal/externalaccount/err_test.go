// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import "testing"

func TestError(t *testing.T) {
	e := Error{
		"42",
		"http:thisIsAPlaceholder",
		"The Answer!",
	}
	want := "got error code 42 from http:thisIsAPlaceholder: The Answer!"
	if got := e.Error(); got != want {
		t.Errorf("Got error message %q; want %q", got, want)
	}
}
