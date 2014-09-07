// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockTransport struct {
	rt func(req *http.Request) (resp *http.Response, err error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return t.rt(req)
}

func newTestConf(url string) *Config {
	conf, _ := NewConfig(&Options{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes: []string{
			"scope1",
			"scope2",
		},
	}, url+"/auth", url+"/token")
	return conf
}

func TestAuthCodeURL(t *testing.T) {
	conf := newTestConf("server")
	url := conf.AuthCodeURL("foo", "offline", "force")
	if url != "server/auth?access_type=offline&approval_prompt=force&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=foo" {
		t.Fatalf("Auth code URL doesn't match the expected, found: %v", url)
	}
}

func TestAuthCodeURL_Optional(t *testing.T) {
	conf, _ := NewConfig(&Options{
		ClientID: "CLIENT_ID",
	}, "auth-url", "token-url")
	url := conf.AuthCodeURL("", "", "")
	if url != "auth-url?client_id=CLIENT_ID&response_type=code" {
		t.Fatalf("Auth code URL doesn't match the expected, found: %v", url)
	}
}

func TestExchangeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "client_id=CLIENT_ID&code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL&scope=scope1+scope2" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newTestConf(ts.URL)
	tok, err := conf.Exchange("exchange-code")
	if err != nil {
		t.Errorf("Failed retrieving token: %s.", err)
	}
	if tok.Expired() {
		t.Errorf("Token shouldn't be expired.")
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Wrong access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Wrong token type, %#v.", tok.TokenType)
	}
}

func TestExchangeRequest_JsonResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "client_id=CLIENT_ID&code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL&scope=scope1+scope2" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "90d64460d14870c08c81352a05dedd3465940a7c", "scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	conf := newTestConf(ts.URL)
	tok, err := conf.Exchange("exchange-code")
	if err != nil {
		t.Errorf("Failed retrieving token: %s.", err)
	}
	if tok.Expired() {
		t.Errorf("Token shouldn't be expired.")
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Wrong access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Wrong token type, %#v.", tok.TokenType)
	}
}

func TestExchangeRequest_NonBasicAuth(t *testing.T) {
	conf, _ := NewConfig(&Options{
		ClientID: "CLIENT_ID",
	}, "https://accounts.google.com/auth",
		"https://accounts.google.com/token")
	tr := &mockTransport{
		rt: func(r *http.Request) (w *http.Response, err error) {
			headerAuth := r.Header.Get("Authorization")
			if headerAuth != "" {
				t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
			}
			return nil, errors.New("no response")
		},
	}
	conf.Client = &http.Client{Transport: tr}
	conf.Exchange("code")
}

func TestTokenRefreshRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
		}
	}))
	defer ts.Close()
	conf := newTestConf(ts.URL)
	conf.FetchToken(&Token{RefreshToken: "REFRESH_TOKEN"})
}

func TestNewTransportWithCode(t *testing.T) {
	exchanged := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/token" {
			exchanged = true
		}
	}))
	defer ts.Close()
	conf := newTestConf(ts.URL)
	conf.NewTransportWithCode("exchange-code")
	if !exchanged {
		t.Errorf("NewTransportWithCode should have exchanged the code, but it didn't.")
	}
}

func TestFetchWithNoRefreshToken(t *testing.T) {
	fetcher := newTestConf("")
	_, err := fetcher.FetchToken(&Token{})
	if err == nil {
		t.Fatalf("Fetch should return an error if no refresh token is set")
	}
}
