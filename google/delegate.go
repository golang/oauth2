// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
        "context"
        "fmt"
        "strconv"
        "sync"
        "time"

        "golang.org/x/oauth2"
        "google.golang.org/api/iamcredentials/v1"
)

// DelegateTokenSource allows a TokenSource issued to a user or
// service account to impersonate another.  The target service account
// must grant the orginating credential principal the
// "Service Account Token Creator" IAM role:
// https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role
//
//  rootSource (TokenSource): The root TokenSource
//     used as to acquire the delegated identity TokenSource.
//     rootSource *must* include scopes that includes
//     "https://www.googleapis.com/auth/iam"
//  principal (string): The service account to impersonate.
//  new_scopes ([]string): Scopes to request during the
//     authorization grant.
//  delegates ([]string): The chained list of delegates required
//     to grant the final access_token.
//  lifetime (int): Number of seconds the delegated credential should
//     be valid for (upto 3600).
//
// Usage:
//   principal := "impersonated-account@project.iam.gserviceaccount.com"
//   lifetime := 30
//   delegates := []string{}
//   newScopes := []string{storage.ScopeReadOnly}
//   rootTokenSource, err := google.DefaultTokenSource(ctx,
//           "https://www.googleapis.com/auth/iam")
//   delegatetokenSource, err := google.DelegateTokenSource(ctx,
//       rootTokenSource,
//           principal, lifetime, delegates, newScopes)
//   storeageClient, _ = storage.NewClient(ctx,
//       option.WithTokenSource(delegatetokenSource))

// Note that this is not a standard OAuth flow, but rather uses Google Cloud
// IAMCredentials API to exchange one oauth token for an impersonated account
// see: https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken
func DelegateTokenSource(ctx context.Context, rootSource oauth2.TokenSource,
        principal string, lifetime int, delegates []string,
        newScopes []string) (oauth2.TokenSource, error) {

        return &delegateTokenSource{
                ctx:        ctx,
                rootSource: rootSource,
                principal:  principal,
                lifetime:   strconv.Itoa(lifetime) + "s",
                delegates:  delegates,
                newScopes:  newScopes,
        }, nil
}

type delegateTokenSource struct {
        ctx        context.Context
        rootSource oauth2.TokenSource
        principal  string
        lifetime   string
        delegates  []string
        newScopes  []string
}

var (
        mu  sync.Mutex
        tok *oauth2.Token
)

func (ts *delegateTokenSource) Token() (*oauth2.Token, error) {

        mu.Lock()
        defer mu.Unlock()

        if tok.Valid() {
                return tok, nil
        }

        client := oauth2.NewClient(context.Background(), ts.rootSource)

        service, err := iamcredentials.New(client)
        if err != nil {
                return nil, fmt.Errorf("Error creating IAMCredentials: %v", err)
        }
        name := "projects/-/serviceAccounts/" + ts.principal
        tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
                Lifetime:  ts.lifetime,
                Delegates: ts.delegates,
                Scope:     ts.newScopes,
        }
        at, err := service.Projects.ServiceAccounts.GenerateAccessToken(name, tokenRequest).Do()
        if err != nil {
                return nil, fmt.Errorf("Error calling GenerateAccessToken: %v", err)
        }

        expireAt, err := time.Parse(time.RFC3339, at.ExpireTime)
        if err != nil {
                return nil, fmt.Errorf("Error parsing ExpireTime: %v", err)
        }

        tok = &oauth2.Token{
                AccessToken: at.AccessToken,
                Expiry:      expireAt,
        }

        return tok, nil
}
