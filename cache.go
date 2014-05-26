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
	// Reads a cached token.
	// It may return a nil value if no token is cached.
	Read() (token *Token, err error)
	// Write writes a token to the specified file.
	Write(token *Token)
}

// NewFileCache creates a new file cache.
func NewFileCache(filename string) (cache *FileCache) {
	return &FileCache{filename: filename}
}

// FileCache represents a file based token cacher.
type FileCache struct {
	// Handler to be invoked if an error occurs during writing.
	ErrorHandler func(error)

	filename string
}

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
func (f *FileCache) Write(token *Token) {
	data, err := json.Marshal(token)
	if err == nil {
		err = ioutil.WriteFile(f.filename, data, 0644)
	}
	if f.ErrorHandler != nil {
		f.ErrorHandler(err)
	}
}
