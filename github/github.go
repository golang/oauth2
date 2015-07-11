// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package github provides constants for using OAuth2 to access Github.
package github // import "golang.org/x/oauth2/github"

import (
	"golang.org/x/oauth2"
	"golang.org/x/net/context"
)

// Endpoint is Github's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

type BasicAuth struct {
	context.Context
	oauth2.Config
}

//set username/password and postbody in the context
func (gh BasicAuth) Token () (tk *oauth2.Token, err error) {

    return gh.Config.GetTokenBasicAuth(gh.Context, FromContext)

}

//typesafe context acccessors
type key int

var CredsKey key = 0

func NewContext(ctx context.Context, ba *oauth2.Creds) context.Context {
	return context.WithValue(ctx, CredsKey, ba)
}

func FromContext(ctx context.Context) (*oauth2.Creds, bool) {
	ba, ok := ctx.Value(CredsKey).(*oauth2.Creds)
	return ba, ok
}
