// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Cache represents a token cacher.
type Cache interface {
	// Reads a cached token. It may return nil if none is cached.
	Read() (*Token, error)
	// Write writes a token to the cache.
	Write(*Token) error
}

// NewFileCache creates a new file cache.
func NewFileCache(filename string) (cache *FileCache) {
	return &FileCache{filename: filename}
}

// FileCache represents a file based token cacher.
type FileCache struct {
	filename string
}

// Read reads the token from the cache file. If there exists no cache
// file, it returns nil for the token.
func (f *FileCache) Read() (token *Token, err error) {
	data, err := ioutil.ReadFile(f.filename)
	if os.IsNotExist(err) {
		// no token has cached before, skip reading
		return nil, nil
	}
	if err != nil {
		return
	}
	if err = json.Unmarshal(data, &token); err != nil {
		return
	}
	return
}

// Write writes a token to the specified file.
func (f *FileCache) Write(token *Token) error {
	data, err := json.Marshal(token)
	if err == nil {
		err = ioutil.WriteFile(f.filename, data, 0644)
	}
	return err
}
