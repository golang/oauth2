// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dcrp implements the OAuth 2.0 Dynamic Client Registration Protocol.
// This specification defines mechanisms for dynamically registering OAuth 2.0 clients with authorization servers.
//
// See https://tools.ietf.org/html/rfc7591

package dcrp // import "golang.org/x/oauth2/dcrp"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Config describes Dynamic Client Registration configuration
type Config struct {
	// InitialAccessToken specifies access token used to get access to get access to
	// client registration endpoint URL. The method by which the initial access token
	// is obtained by the client or developer is generally out of band
	InitialAccessToken string

	// ClientRegistrationEndpointURL specifies authorization server's client registration endpoint URL
	// This is a constant specific to each server.
	ClientRegistrationEndpointURL string

	// Metadata specifies client metadata to be used for client registration
	Metadata
}

// Metadata describes client metadata.
// Registered clients have a set of metadata values associated with their
// client identifier at an authorization server. The implementation
// and use of all client metadata fields is OPTIONAL
type Metadata struct {
	// RedirectURIs specifies redirection URI strings for use in
	// redirect-based flows such as the "authorization code" and "implicit".
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// TokenEndpointAuthMethod specifies indicator of the requested authentication
	// method for the token endpoint
	// Possible values are:
	// "none": The client is a public client and does not have a client secret.
	// "client_secret_post": The client uses the HTTP POST parameters
	// "client_secret_basic": The client uses HTTP Basic
	// Additional values can be defined or absolute URIs can also be used
	// as values for this parameter without being registered.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes specifies grant type strings that the client can use at the token endpoint
	// Possible values are:
	// "authorization_code": The authorization code grant type
	// "implicit": The implicit grant type
	// "password": The resource owner password credentials grant type
	// "client_credentials": The client credentials grant type
	// "refresh_token": The refresh token grant type
	// "urn:ietf:params:oauth:grant-type:jwt-bearer": The JWT Bearer Token Grant Type
	// "urn:ietf:params:oauth:grant-type:saml2-bearer": The SAML 2.0 Bearer Assertion Grant
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes specifies response type strings that the client can
	// use at the authorization endpoint.
	// Possible values are:
	// "code": The "authorization code" response
	// "token": The "implicit" response
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientName specifies Human-readable string name of the client
	// to be presented to the end-user during authorization
	ClientName string `json:"client_name,omitempty"`

	// ClientURI specifies URL of a web page providing information about the client.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI specifies URL of a logo of the client
	LogoURI string `json:"logo_uri,omitempty"`

	// Scopes specifies scope values that the client can use when requesting access tokens.
	Scopes []string `json:"-"`

	// Scope specifies wire-level scopes representation
	Scope string `json:"scope,omitempty"`

	// Contacts specifies ways to contact people responsible for this client,
	// typically email addresses.
	Contacts []string `json:"contacts,omitempty"`

	// TermsOfServiceURI specifies URL of a human-readable terms of service
	// document for the client
	TermsOfServiceURI string `json:"tos_uri,omitempty"`

	// PolicyURI specifies URL of a human-readable privacy policy document
	PolicyURI string `json:"policy_uri,omitempty"`

	// JWKSURI specifies URL referencing the client's JWK Set [RFC7517] document,
	// which contains the client's public keys.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// JWKS specifies the client's JWK Set [RFC7517] document, which contains
	// the client's public keys.  The value of this field MUST be a JSON
	// containing a valid JWK Set.
	JWKS string `json:"jwks,omitempty"`

	// SoftwareID specifies UUID assigned by the client developer or software publisher
	// used by registration endpoints to identify the client software.
	SoftwareID string `json:"software_id,omitempty"`

	// SoftwareVersion specifies version of the client software
	SoftwareVersion string `json:"software_version,omitempty"`

	// SoftwareStatement specifies client metadata values about the client software
	// as claims.  This is a string value containing the entire signed JWT.
	SoftwareStatement string `json:"software_statement,omitempty"`

	// Optional specifies optional fields
	Optional map[string]string `json:"-"`
}

// prepareForWire prepares Metadata struct to be ready to sent to server.
func (md *Metadata) prepareForWire() {
	md.Scope = strings.Join(md.Scopes, " ")
}

// prepareFromWire prepares Metadata to be ready to be used by user
func (md *Metadata) prepareFromWire() {
	md.Scopes = strings.Split(md.Scope, " ")
}

// Response describes Client Information Response as specified in Section 3.2.1 of RFC 7591
type Response struct {
	// ClientID specifies client identifier string. REQUIRED
	ClientID string `json:"client_id"`

	// ClientSecret specifies client secret string. OPTIONAL
	ClientSecret string `json:"client_secret"`

	// ClientIDIssuedAt specifies time at which the client identifier was issued. OPTIONAL
	ClientIDIssuedAt time.Time `json:"client_id_issued_at"`

	// ClientSecretExpiresAt specifies time at which the client	secret will expire
	// or 0 if it will not expire. REQUIRED if "client_secret" is issued.
	ClientSecretExpiresAt time.Time `json:"client_secret_expires_at"`

	// Additionally, the authorization server MUST return all registered metadata about this client
	Metadata `json:",inline"`
}

// Register performs Dynamic Client Registration dy doing round trip to authorization server
func (c *Config) Register() (*Response, error) {
	c.Metadata.prepareForWire()
	jsonMetadata, err := json.Marshal(c.Metadata)
	if err != nil {
		return nil, err
	}
	req, err := newHTTPRequest(c.ClientRegistrationEndpointURL, c.InitialAccessToken, jsonMetadata)
	if err != nil {
		return nil, err
	}
	return doRoundTrip(req)
}

// RegistrationError describes errors returned by auth server during client registration process
type RegistrationError struct {
	Response *http.Response
	Body     []byte
}

func (r *RegistrationError) Error() string {
	return fmt.Sprintf("oauth2: cannot register client: %v\nResponse: %s", r.Response.Status, r.Body)
}

// newHTTPRequest returns a new *http.Request to  be used for client registration
// It has header fields specified
func newHTTPRequest(registrationURL, initialAccessToken string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", registrationURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if initialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+initialAccessToken)
	}
	return req, nil
}

// doRoundTrip performs communication with authorization server for client registration
func doRoundTrip(req *http.Request) (*Response, error) {
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2 dcrp: cannot read server response: %v", err)
	}
	// The server responds with an HTTP 201 Created status code and a body of type "application/json"
	if code := resp.StatusCode; code != 201 {
		return nil, &RegistrationError{
			Response: resp,
			Body:     body,
		}
	}

	// The response contains the client identifier as well as the client secret,
	// if the client is a confidential client.
	// The response MAY contain additional fields
	cr := &Response{}
	if err = json.Unmarshal(body, cr); err != nil {
		return nil, err
	}
	cr.Metadata.prepareFromWire()
	if cr.ClientID == "" {
		return nil, errors.New("oauth2 dcrp: server response missing required client_id in body:\n" + string(body))
	}
	return cr, nil
}

// MarshalJSON prepares Response for wire JSON representation
func (r Response) MarshalJSON() ([]byte, error) {
	type Alias Response
	wire := struct {
		ClientIDIssuedAt      int64 `json:"client_id_issued_at"`
		ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`
		Alias
	}{
		ClientIDIssuedAt:      r.ClientIDIssuedAt.Unix(),
		ClientSecretExpiresAt: r.ClientSecretExpiresAt.Unix(),
		Alias:                 (Alias)(r),
	}
	return json.Marshal(wire)
}

// MarshalJSON prepares Response from wire JSON representation
func (r *Response) UnmarshalJSON(data []byte) error {
	type Alias Response
	wire := &struct {
		ClientIDIssuedAt      int64 `json:"client_id_issued_at"`
		ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.ClientIDIssuedAt = time.Unix(wire.ClientIDIssuedAt, 0)
	r.ClientSecretExpiresAt = time.Unix(wire.ClientSecretExpiresAt, 0)
	return nil
}
