// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2

import (
	"encoding/json"
	"io/ioutil"
)

// Cache represents a token cacher.
type Cache interface {
	// Read reads a cache token from the specified file.
	Read() (token *Token, err error)
	// Write writes a token to the specified file.
	Write(token *Token) (err error)
}

// NewFileCache creates a new file cache.
func NewFileCache(filename string) *FileCache {
	return &FileCache{filename: filename}
}

// FileCache represents a file based token cacher.
type FileCache struct {
	filename string
}

// Read reads a cache token from the specified file.
func (f *FileCache) Read() (token *Token, err error) {
	data, err := ioutil.ReadFile(f.filename)
	if err != nil {
		return nil, err
	}
	token = &Token{}
	err = json.Unmarshal(data, &token)
	return token, err
}

// Write writes a token to the specified file.
func (f *FileCache) Write(token *Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f.filename, data, 0644)
}
