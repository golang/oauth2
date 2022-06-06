// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package authhandler implements a TokenSource to support
// "three-legged OAuth 2.0" via a custom AuthorizationHandler.
package authhandler

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

const (
	// Parameter keys for AuthCodeURL method to support PKCE.
	codeChallengeKey       = "code_challenge"
	codeChallengeMethodKey = "code_challenge_method"

	// Parameter key for Exchange method to support PKCE.
	codeVerifierKey = "code_verifier"
)

// PKCEParams holds parameters to support PKCE.
type PKCEParams struct {
	CodeChallenge       string // The unpadded, base64-url-encoded string of the encrypted codeVerifier.
	CodeChallengeMethod string // The encryption method (ex. S256).
	CodeVerifier        string // The original, non-encrypted secret.
}

// AuthorizationHandler is a 3-legged-OAuth helper that prompts
// the user for OAuth consent at the specified auth code URL
// and returns an auth code and state upon approval.
type AuthorizationHandler func(authCodeURL string) (code string, state string, err error)

// TokenSource returns an oauth2.TokenSource that fetches access tokens
// using 3-legged-OAuth flow.
//
// The provided context.Context is used for oauth2 Exchange operation.
//
// The provided oauth2.Config should be a full configuration containing AuthURL,
// TokenURL, and Scope.
//
// An environment-specific AuthorizationHandler is used to obtain user consent.
//
// Per the OAuth protocol, a unique "state" string should be specified here.
// This token source will verify that the "state" is identical in the request
// and response before exchanging the auth code for OAuth token to prevent CSRF
// attacks.
//
// The pkce parameter supports PKCE flow.
// See https://www.oauth.com/oauth2-servers/pkce/ for more info.
func TokenSourceWithPKCE(ctx context.Context, config *oauth2.Config, state string, authHandler AuthorizationHandler, pkce *PKCEParams) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, authHandlerSource{config: config, ctx: ctx, authHandler: authHandler, state: state, pkce: pkce})
}

// Deprecated: Use TokenSourceWithPKCE instead.
func TokenSource(ctx context.Context, config *oauth2.Config, state string, authHandler AuthorizationHandler) oauth2.TokenSource {
	return TokenSourceWithPKCE(ctx, config, state, authHandler, nil)
}

type authHandlerSource struct {
	ctx         context.Context
	config      *oauth2.Config
	authHandler AuthorizationHandler
	state       string
	pkce        *PKCEParams
}

func (source authHandlerSource) Token() (*oauth2.Token, error) {
	// Step 1: Obtain auth code.
	var authCodeUrlOptions []oauth2.AuthCodeOption
	if source.pkce != nil {
		authCodeUrlOptions = []oauth2.AuthCodeOption{oauth2.SetAuthURLParam(codeChallengeKey, source.pkce.CodeChallenge),
			oauth2.SetAuthURLParam(codeChallengeMethodKey, source.pkce.CodeChallengeMethod)}
	}
	url := source.config.AuthCodeURL(source.state, authCodeUrlOptions...)
	code, state, err := source.authHandler(url)
	if err != nil {
		return nil, err
	}
	if state != source.state {
		return nil, errors.New("state mismatch in 3-legged-OAuth flow")
	}

	// Step 2: Exchange auth code for access token.
	var exchangeOptions []oauth2.AuthCodeOption
	if source.pkce != nil {
		exchangeOptions = []oauth2.AuthCodeOption{oauth2.SetAuthURLParam(codeVerifierKey, source.pkce.CodeVerifier)}
	}
	return source.config.Exchange(source.ctx, code, exchangeOptions...)
}
