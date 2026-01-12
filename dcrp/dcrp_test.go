// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dcrp

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	newClientMetadata = Metadata{
		RedirectURIs: []string{
			"https://redirect1.example.com",
			"https://redirect2.example.com",
			"https://redirect3.example.com",
		},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"client_credentials",
		},
		ResponseTypes: []string{
			"token",
		},
		ClientName: "test client",
		ClientURI:  "https://testclient.example.com",
		LogoURI:    "https://testclient.example.com/logo.png",
		Scopes: []string{
			"email",
			"profile",
		},
		Contacts: []string{
			"email1@example.com",
			"email2@example.com",
		},
		TermsOfServiceURI: "https://testclent.example.com/tos.txt",
		PolicyURI:         "https://testclient.example.com/policy.txt",
		JWKSURI:           "https://testclient.example.com/jwks.json",
		JWKS:              "public keys go here",
		SoftwareID:        "01234567-0123-0123-0123-01234567890a",
		SoftwareVersion:   "1",
		SoftwareStatement: "statement",
	}

	wantClientRegistrationRequestJSON = `{
			"redirect_uris": [
				"https://redirect1.example.com",
				"https://redirect2.example.com",
				"https://redirect3.example.com"
			],
			"token_endpoint_auth_method": "client_secret_basic",
			"grant_types": [
				"client_credentials"
			],
			"response_types": [
				"token"
			],
			"client_name": "test client",
			"client_uri": "https://testclient.example.com",
			"logo_uri": "https://testclient.example.com/logo.png",
			"scope": "email profile",
			"contacts": [
				"email1@example.com",
				"email2@example.com"
			],
			"tos_uri": "https://testclent.example.com/tos.txt",
			"policy_uri": "https://testclient.example.com/policy.txt",
			"jwks_uri": "https://testclient.example.com/jwks.json",
			"jwks": "public keys go here",
			"software_id": "01234567-0123-0123-0123-01234567890a",
			"software_version": "1",
			"software_statement": "statement"
}`

	wantClientID         = "ASD123"
	wantClientIDIssuedAt = time.Unix(time.Now().Unix(), 0)
)

func newConf(endpoint string) *Config {
	return &Config{
		InitialAccessToken:            "123",
		ClientRegistrationEndpointURL: endpoint,
		Metadata:                      newClientMetadata,
	}
}

// jsonEqual compares the JSON in two byte slices.
func jsonEqual(a, b []byte) (bool, error) {
	var json1, json2 interface{}
	if err := json.Unmarshal(a, &json1); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &json2); err != nil {
		return false, err
	}
	return reflect.DeepEqual(json1, json2), nil
}

// metadataEqual compares two items of metadata, ignoring wire scope data.
func metadataEqual(a, b Metadata) (bool, error) {
	a.Scope = ""
	b.Scope = ""
	return reflect.DeepEqual(a, b), nil
}

func TestDynamicClientRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/client-registration" {
			t.Errorf("Unexpected URL: %q", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "" {
			if !strings.HasPrefix(headerAuth, "Bearer ") {
				t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
			}
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, "application/json"; got != want {
			t.Errorf("Content-Type = %q; want %q", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			r.Body.Close()
		}
		if err != nil {
			t.Errorf("failed reading request body: %s.", err)
		}
		// Check wire JSON data representation is as expected
		equal, err := jsonEqual(body, []byte(wantClientRegistrationRequestJSON))
		if !equal {
			t.Errorf("Unexpected dynamic client registration protocol payload.\ngot: %s\nwant: %s\n", body, wantClientRegistrationRequestJSON)
		}
		var md Metadata
		err = json.Unmarshal(body, &md)
		if err != nil {
			t.Errorf("Unexpected dynamic client registration protocol payload.\n%s\nError: %v", body, err)
		}

		// Prepare Response with registered client data
		clientInfo := Response{}
		clientInfo.Metadata = md
		clientInfo.ClientID = wantClientID
		clientInfo.ClientIDIssuedAt = wantClientIDIssuedAt
		resp, err := json.Marshal(clientInfo)
		if err != nil {
			t.Errorf("Unable to marshal Response\nError: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, string(resp))
	}))
	defer ts.Close()

	conf := newConf(ts.URL + "/client-registration")
	resp, err := conf.Register()
	if err != nil {
		t.Error(err)
	}
	if resp.ClientID != wantClientID {
		t.Errorf("Unable to register client. Incorrect ClientID\ngot=%s\nwant=%s\n", resp.ClientID, wantClientID)
	}
	if resp.ClientIDIssuedAt != wantClientIDIssuedAt {
		t.Errorf("Unable to register client. Incorrect ClientIDIssuedAt\ngot=%s\nwant=%s\n", resp.ClientIDIssuedAt, wantClientIDIssuedAt)
	}
	equal, err := metadataEqual(newClientMetadata, resp.Metadata)
	if !equal {
		t.Errorf("Unexpected dynamic client registration protocol metadata returned.\ngot=%v\nwant=%v\n", resp.Metadata, newClientMetadata)
	}
}
