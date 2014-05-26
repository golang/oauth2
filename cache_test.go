// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"io/ioutil"
	"path"
	"testing"
)

var tokenBody = `{"access_token":"abc123","token_type":"Bearer","refresh_token":"def789","expiry":"0001-01-01T00:00:00Z"}`

func TestNewFileCacheNotExist(t *testing.T) {
	cache, err := NewFileCache("/path/that/doesnt/exist")
	if err != nil {
		t.Fatalf("NewFileCache shouldn't return an error for if cache file doesn't exist, but returned %v", err)
	}
	if cache == nil {
		t.Fatalf("A file cache should be inited with a non existing cache file")
	}
}

func TestNewFileCache(t *testing.T) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(tokenBody)
	if err != nil {
		t.Fatal(err)
	}

	cache, err := NewFileCache(f.Name())
	if err != nil {
		t.Fatalf("Cache should have read the file cache at %v, but recieved %v", f.Name(), err)
	}
	token := cache.Token()
	if token.AccessToken != "abc123" {
		t.Fatalf("Cached access token is %v, expected to be abc123", token.AccessToken)
	}
	if token.RefreshToken != "def789" {
		t.Fatalf("Cached refresh token is %v, expected to be def789", token.RefreshToken)
	}
}

func TestFileCacheWrite(t *testing.T) {
	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}

	cache, err := NewFileCache(path.Join(dirName, "cache-file"))
	cache.ErrorHandler = func(err error) {
		if err != nil {
			t.Fatalf("Cache write should have been succeeded succesfully, recieved %v", err)
		}
	}
	if err != nil {
		t.Fatal(err)
	}

	cache.Write(&Token{
		AccessToken:  "abc123",
		TokenType:    "Bearer",
		RefreshToken: "def789",
	})

	data, err := ioutil.ReadFile(cache.filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != tokenBody {
		t.Fatalf("Written token is different than the expected, %v is found", data)
	}
}
