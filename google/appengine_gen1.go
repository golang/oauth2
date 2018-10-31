// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appengine

package google

import (
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"google.golang.org/appengine"
)

func init() {
	appengineTokenFunc = appengine.AccessToken
	appengineAppIDFunc = appengine.AppID
}

// AppEngineTokenSource returns a token source that fetches tokens from either
// the current application's service account or from the metadata server,
// depending on the App Engine environment. See below for environment-specific
// details. If you are implementing a 3-legged OAuth 2.0 flow on App Engine that
// involves user accounts, see oauth2.Config instead.
//
// First generation App Engine runtimes (<= Go 1.9):
// AppEngineTokenSource returns a token source that fetches tokens issued to the
// current App Engine application's service account. The provided context must have
// come from appengine.NewContext.
//
// Second generation App Engine runtimes (>= Go 1.11) and App Engine flexible:
// AppEngineTokenSource is DEPRECATED on second generation runtimes and on the
// flexible environment. It delegates to ComputeTokenSource, and the provided
// context and scopes are not used. Please use DefaultTokenSource (or ComputeTokenSource,
// which DefaultTokenSource will use in this case) instead.
func AppEngineTokenSource(ctx context.Context, scope ...string) oauth2.TokenSource {
	scopes := append([]string{}, scope...)
	sort.Strings(scopes)
	return &appEngineTokenSource{
		ctx:    ctx,
		scopes: scopes,
		key:    strings.Join(scopes, " "),
	}
}

// aeTokens helps the fetched tokens to be reused until their expiration.
var (
	aeTokensMu sync.Mutex
	aeTokens   = make(map[string]*tokenLock) // key is space-separated scopes
)

type tokenLock struct {
	mu sync.Mutex // guards t; held while fetching or updating t
	t  *oauth2.Token
}

type appEngineTokenSource struct {
	ctx    context.Context
	scopes []string
	key    string // to aeTokens map; space-separated scopes
}

func (ts *appEngineTokenSource) Token() (*oauth2.Token, error) {
	aeTokensMu.Lock()
	tok, ok := aeTokens[ts.key]
	if !ok {
		tok = &tokenLock{}
		aeTokens[ts.key] = tok
	}
	aeTokensMu.Unlock()

	tok.mu.Lock()
	defer tok.mu.Unlock()
	if tok.t.Valid() {
		return tok.t, nil
	}
	access, exp, err := appengineTokenFunc(ts.ctx, ts.scopes...)
	if err != nil {
		return nil, err
	}
	tok.t = &oauth2.Token{
		AccessToken: access,
		Expiry:      exp,
	}
	return tok.t, nil
}
