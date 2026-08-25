// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRetrieveToken_InParams(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.FormValue("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		if got, want := r.FormValue("client_secret"), ""; got != want {
			t.Errorf("client_secret = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()
	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleInParams, styleCache)
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveTokenWithContexts(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()

	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	if err != nil {
		t.Errorf("RetrieveToken (with background context) = %v; want no error", err)
	}

	retrieved := make(chan struct{})
	cancellingts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-retrieved
	}))
	defer cancellingts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RetrieveToken(ctx, clientID, "", cancellingts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	close(retrieved)
	if err == nil {
		t.Errorf("RetrieveToken (with cancelled context) = nil; want error")
	}
}

func TestExpiresInUpperBound(t *testing.T) {
	var e expirationTime
	if err := e.UnmarshalJSON([]byte(fmt.Sprint(int64(math.MaxInt32) + 1))); err != nil {
		t.Fatal(err)
	}
	const want = math.MaxInt32
	if e != want {
		t.Errorf("expiration time = %v; want %v", e, want)
	}
}

// TestRetrieveToken_AuthStyleUnknown_BothProbesFail verifies that when
// the auth style is unknown and both the header-probe and the params-probe
// fail, RetrieveToken returns both errors joined together rather than only
// the second one. This matters because the first request may have already
// consumed the authorization code at the provider, so the second error is
// often a misleading consequence (e.g. "code already redeemed") of an
// unrelated first failure (e.g. misconfiguration).
func TestRetrieveToken_AuthStyleUnknown_BothProbesFail(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"

	const headerErrCode = "invalid_client"
	const paramsErrCode = "invalid_grant"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if r.Header.Get("Authorization") != "" {
			io.WriteString(w, `{"error":"`+headerErrCode+`"}`)
			return
		}
		io.WriteString(w, `{"error":"`+paramsErrCode+`"}`)
	}))
	defer ts.Close()

	_, err := RetrieveToken(context.Background(), clientID, "secret", ts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	if err == nil {
		t.Fatalf("RetrieveToken returned nil error; want joined error")
	}

	msg := err.Error()
	if !strings.Contains(msg, headerErrCode) || !strings.Contains(msg, paramsErrCode) {
		t.Errorf("error = %q; want it to mention both %q and %q", msg, headerErrCode, paramsErrCode)
	}

	var re *RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("errors.As(err, *RetrieveError) = false; want true")
	}
}

// TestRetrieveToken_AuthStyleUnknown_HeaderFailsParamsSucceeds verifies that
// the probe still succeeds transparently when the header attempt fails but
// the params attempt succeeds. This is the long-standing behavior we must
// not break with the error-joining change.
func TestRetrieveToken_AuthStyleUnknown_HeaderFailsParamsSucceeds(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		if got, want := r.FormValue("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()

	tok, err := RetrieveToken(context.Background(), clientID, "secret", ts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	if err != nil {
		t.Fatalf("RetrieveToken = %v; want no error", err)
	}
	if tok.AccessToken != "ACCESS_TOKEN" {
		t.Errorf("AccessToken = %q; want %q", tok.AccessToken, "ACCESS_TOKEN")
	}
}

func TestAuthStyleCache(t *testing.T) {
	var c LazyAuthStyleCache

	cases := []struct {
		url      string
		clientID string
		style    AuthStyle
	}{
		{
			"https://host1.example.com/token",
			"client_1",
			AuthStyleInHeader,
		}, {
			"https://host2.example.com/token",
			"client_2",
			AuthStyleInParams,
		}, {
			"https://host1.example.com/token",
			"client_3",
			AuthStyleInParams,
		},
	}

	for _, tt := range cases {
		t.Run(tt.clientID, func(t *testing.T) {
			cc := c.Get()
			got, ok := cc.lookupAuthStyle(tt.url, tt.clientID)
			if ok {
				t.Fatalf("unexpected auth style found on first request: %v", got)
			}

			cc.setAuthStyle(tt.url, tt.clientID, tt.style)

			got, ok = cc.lookupAuthStyle(tt.url, tt.clientID)
			if !ok {
				t.Fatalf("auth style not found in cache")
			}

			if got != tt.style {
				t.Fatalf("auth style mismatch, got=%v, want=%v", got, tt.style)
			}
		})
	}
}
