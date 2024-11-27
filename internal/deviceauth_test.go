// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDeviceAuth_ClientAuthnInParams(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"
	const clientSecret = "client-secret"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.FormValue("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		if got, want := r.FormValue("client_secret"), clientSecret; got != want {
			t.Errorf("client_secret = %q; want %q", got, want)
		}
		io.WriteString(w, `{"device_code":"code","user_code":"user_code","verification_uri":"http://example.device.com","expires_in":300,"interval":5}`)
	}))
	defer ts.Close()
	_, err := RetrieveDeviceAuth(context.Background(), clientID, clientSecret, ts.URL, url.Values{}, AuthStyleInParams, styleCache)
	if err != nil {
		t.Errorf("RetrieveDeviceAuth = %v; want no error", err)
	}
}

func TestDeviceAuth_ClientAuthnInHeader(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"
	const clientSecret = "client-secret"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		if got, want := u, clientID; got != want {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		if got, want := p, clientSecret; got != want {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		io.WriteString(w, `{"device_code":"code","user_code":"user_code","verification_uri":"http://example.device.com","expires_in":300,"interval":5}`)
	}))
	defer ts.Close()
	_, err := RetrieveDeviceAuth(context.Background(), clientID, clientSecret, ts.URL, url.Values{}, AuthStyleInHeader, styleCache)
	if err != nil {
		t.Errorf("RetrieveDeviceAuth = %v; want no error", err)
	}
}

func TestDeviceAuth_ClientAuthnProbe(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"
	const clientSecret = "client-secret"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		if got, want := u, clientID; got != want {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		if got, want := p, clientSecret; got != want {
			io.WriteString(w, `{"error":"invalid_client"}`)
			w.WriteHeader(http.StatusBadRequest)
		}
		io.WriteString(w, `{"device_code":"code","user_code":"user_code","verification_uri":"http://example.device.com","expires_in":300,"interval":5}`)
	}))
	defer ts.Close()
	_, err := RetrieveDeviceAuth(context.Background(), clientID, clientSecret, ts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	if err != nil {
		t.Errorf("RetrieveDeviceAuth = %v; want no error", err)
	}
}
