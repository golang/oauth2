// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"io/ioutil"
)

// Cache represents a token cacher.
type Cache interface {
	// Read reads a cache token from the specified file.
	Read() (token *Token)
	// Write writes a token to the specified file.
	Write(token *Token)
}

// NewFileCache creates a new file cache.
func NewFileCache(filename string) *FileCache {
	return &FileCache{filename: filename}
}

// FileCache represents a file based token cacher.
type FileCache struct {
	filename         string
	ErrorHandlerFunc func(error)
}

// Read reads a cache token from the specified file.
func (f *FileCache) Read() (token *Token) {
	data, err := ioutil.ReadFile(f.filename)
	if err == nil {
		err = json.Unmarshal(data, token)
	}
	if f.ErrorHandlerFunc != nil {
		f.ErrorHandlerFunc(err)
	}
	return
}

// Write writes a token to the specified file.
func (f *FileCache) Write(token *Token) {
	data, err := json.Marshal(token)
	if err == nil {
		err = ioutil.WriteFile(f.filename, data, 0644)
	}
	if f.ErrorHandlerFunc != nil {
		f.ErrorHandlerFunc(err)
	}
}
