// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"io/ioutil"
	"net/http"
	"testing"
)

type mockTransport struct {
	rt func(req *http.Request) (resp *http.Response, err error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return t.rt(req)
}

func newTestConf() *Config {
	conf, _ := NewConfig(&Options{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes: []string{
			"scope1",
			"scope2",
		},
		AccessType:     "offline",
		ApprovalPrompt: "force",
	}, "auth-url", "token-url")
	return conf
}

func TestAuthCodeURL(t *testing.T) {
	conf := newTestConf()
	url := conf.AuthCodeURL("foo")
	if url != "auth-url?access_type=offline&approval_prompt=force&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=foo" {
		t.Fatalf("Generated auth URL is not the expected. Found %v.", url)
	}
}

func TestExchangePayload(t *testing.T) {
	oldDefaultTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = oldDefaultTransport
	}()

	conf := newTestConf()
	http.DefaultTransport = &mockTransport{
		rt: func(req *http.Request) (resp *http.Response, err error) {
			headerContentType := req.Header.Get("Content-Type")
			if headerContentType != "application/x-www-form-urlencoded" {
				t.Fatalf("Content-Type header is expected to be application/x-www-form-urlencoded, %v found.", headerContentType)
			}
			body, _ := ioutil.ReadAll(req.Body)
			if string(body) != "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL&scope=scope1+scope2" {
				t.Fatalf("Exchange payload is found to be %v", string(body))
			}
			return nil, errors.New("no response")
		},
	}
	conf.Exchange("exchange-code")
}

func TestRefreshPayload(t *testing.T) {
	oldDefaultTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = oldDefaultTransport
	}()
	conf := newTestConf()
	http.DefaultTransport = &mockTransport{
		rt: func(req *http.Request) (resp *http.Response, err error) {
			headerContentType := req.Header.Get("Content-Type")
			if headerContentType != "application/x-www-form-urlencoded" {
				t.Fatalf("Content-Type header is expected to be application/x-www-form-urlencoded, %v found.", headerContentType)
			}
			body, _ := ioutil.ReadAll(req.Body)
			if string(body) != "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
				t.Fatalf("Exchange payload is found to be %v", string(body))
			}
			return nil, errors.New("no response")
		},
	}
	conf.FetchToken(&Token{RefreshToken: "REFRESH_TOKEN"})
}

func TestExchangingTransport(t *testing.T) {
	oldDefaultTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = oldDefaultTransport
	}()

	conf := newTestConf()
	http.DefaultTransport = &mockTransport{
		rt: func(req *http.Request) (resp *http.Response, err error) {
			if req.URL.RequestURI() != "token-url" {
				t.Fatalf("NewTransportWithCode should have exchanged the code, but it didn't.")
			}
			return nil, errors.New("no response")
		},
	}
	conf.NewTransportWithCode("exchange-code")
}

func TestFetchWithNoRedirect(t *testing.T) {
	fetcher := newTestConf()
	_, err := fetcher.FetchToken(&Token{})
	if err == nil {
		t.Fatalf("Fetch should return an error if no refresh token is set")
	}
}
