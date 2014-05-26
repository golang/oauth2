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
	// Token returns the initial token retrieved from the cache,
	// if there is no existing token nil value is returned.
	Token() (token *Token)
	// Write writes a token to the specified file.
	Write(token *Token)
}

// NewFileCache creates a new file cache.
func NewFileCache(filename string) (cache *FileCache, err error) {
	data, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		// no token has cached before, skip reading
		return &FileCache{filename: filename}, nil
	}
	if err != nil {
		return
	}
	var token Token
	if err = json.Unmarshal(data, &token); err != nil {
		return
	}
	cache = &FileCache{filename: filename, initialToken: &token}
	return
}

// FileCache represents a file based token cacher.
type FileCache struct {
	// Handler to be invoked if an error occurs
	// during read or write operations.
	ErrorHandler func(error)

	initialToken *Token
	filename     string
}

// Token returns the initial token read from the cache. It should be used to
// warm the authorization mechanism, token refreshes and later writes don't
// change the returned value. If no token is cached before, returns nil.
func (f *FileCache) Token() (token *Token) {
	return f.initialToken
}

// Write writes a token to the specified file.
func (f *FileCache) Write(token *Token) {
	data, err := json.Marshal(token)
	if err == nil {
		err = ioutil.WriteFile(f.filename, data, 0644)
	}
	if f.ErrorHandler != nil {
		f.ErrorHandler(err)
	}
}
