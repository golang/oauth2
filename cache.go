// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

// CacheRoundTripper is a simple caching transport.
// Example usage:
//   t := &CacherRoundTripper{ TransportDelegate: conf.NewTransport() }
//   client := http.Client{Transport: t}
type CacheRoundTripper struct {
	TransportDelegate Transport
	CacheFile         string
	Config            *Config
}

func loadToken(file string) (*Token, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var token Token
	err = json.Unmarshal(data, &token)
	return &token, err
}

func saveToken(file string, token *Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, data, 0x0700)
}

func obtainToken(conf *Config) (*Token, error) {
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("")
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)
	fmt.Print("Please enter auth code:")
	var exchangeCode string
	if _, err := fmt.Scan(&exchangeCode); err != nil {
		log.Fatal(err)
	}
	return conf.Exchange(exchangeCode)
}

func (c *CacheRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := loadToken(c.CacheFile)
	if err != nil {
		return nil, err
	}
	if token == nil {
		obtainToken(c.Config)
	}
	c.TransportDelegate.SetToken(token)
	resp, err := c.TransportDelegate.RoundTrip(req)
	if err != nil {
		err = saveToken(c.CacheFile, c.TransportDelegate.Token())
	}
	return resp, err
}
