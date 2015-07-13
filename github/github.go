// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package github provides constants for using OAuth2 to access Github.
package github // import "golang.org/x/oauth2/github"

import (
	"bytes"
	"encoding/json"
	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Endpoint is Github's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

// basicAuthRequestBody is the struct for generating the body for the post
//
// its used to generate the postBodyReader that goes into the oauth2Creds with the username/password
type basicAuthRequestBody struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Note         string   `json:"note"`
	Scopes       []string `json:"scopes"`
}

// BasicAuth is a struct which is used to orchestrate the Token call
//
// Token calls take no arguments, but the creds are in the context
// and the oauth2 config is needed too
type BasicAuth struct {
	context.Context
	oauth2.Config
}


// NewBasicAuthClient generates an http client that will do the Basic Auth call to github to get a token
//
// The returned client can be passed to github.NewClient
//
// the api docs are here https://developer.github.com/v3/oauth_authorizations/#create-a-new-authorization
//
func NewBasicAuthClient(oa2 oauth2.Config, username, password, note string, repos []string) (tc *http.Client, err error) {

	postBody := basicAuthRequestBody{
		oa2.ClientID,
		oa2.ClientSecret,
		note,
		repos,
	}

	pb, err := json.Marshal(postBody)
	if err != nil {
		return
	}

	creds := oauth2.Creds{username, password, bytes.NewReader(pb)}

	ctx := NewContext(context.Background(), creds)

	tc = oauth2.NewClient(ctx, BasicAuth{ctx, oa2})

	return

}

//set username/password and postbody in the context
func (gh BasicAuth) Token() (tk *oauth2.Token, err error) {

	return gh.Config.GetTokenBasicAuth(gh.Context, FromContext)

}

//typesafe context acccessors
type key int

var CredsKey key = 0

func NewContext(ctx context.Context, ba oauth2.Creds) context.Context {
	return context.WithValue(ctx, CredsKey, ba)
}

func FromContext(ctx context.Context) (oauth2.Creds, bool) {
	ba, ok := ctx.Value(CredsKey).(oauth2.Creds)
	return ba, ok
}
