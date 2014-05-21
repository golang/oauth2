// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"os"
	"testing"
)

func TestFileCacheErrorHandling(t *testing.T) {
	var lastErr error
	fileCache := NewFileCache("/path/that/doesnt/exist")
	fileCache.ErrorHandlerFunc = func(err error) {
		lastErr = err
	}
	fileCache.Read()
	if !os.IsNotExist(lastErr) {
		t.Fatalf("Read should have invoked the error handling func with os.ErrNotExist, but read err is %v", lastErr)
	}
	lastErr = nil
	fileCache.Write(&Token{})
	if !os.IsNotExist(lastErr) {
		t.Fatalf("Write should have invoked the error handling func with os.ErrNotExist, but read err is %v", lastErr)
	}
}
