// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
        "context"
        "fmt"
        "regexp"
        "strings"
        "sync"
        "time"

        "golang.org/x/oauth2"
        "google.golang.org/api/iamcredentials/v1"
)

var (
        mu  sync.Mutex
        tok *oauth2.Token
)

const emailRegex string = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

// DelegateTokenSource allows a TokenSource issued to a user or
// service account to impersonate another.  The target service account
// must grant the orginating  principal the
// "Service Account Token Creator" IAM role:
// https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role
//
//  rootSource (TokenSource): The root TokenSource
//     used as to acquire the target identity TokenSource.
//     rootSource *must* include scopes that contains
//     "https://www.googleapis.com/auth/iam"
//     or
//     "https://www.googleapis.com/auth/cloud.platform"
//  principal (string): The service account to impersonate.
//  new_scopes ([]string): Scopes to request during the
//     authorization grant.
//  delegates ([]string): The chained list of delegates required
//     to grant the final access_token.
//  lifetime (time.Duration): Number of seconds the delegated credential should
//     be valid for (upto 3600).
//
// Usage:
//   principal := "impersonated-account@project.iam.gserviceaccount.com"
//   lifetime := 30 * time.Second
//   delegates := []string{}
//   newScopes := []string{storage.ScopeReadOnly}
//   rootTokenSource, err := google.DefaultTokenSource(ctx,
//           "https://www.googleapis.com/auth/iam")
//   delegatetokenSource, err := google.DelegateTokenSource(ctx,
//       rootTokenSource,
//       principal, lifetime, delegates, newScopes)
//   storeageClient, _ = storage.NewClient(ctx,
//       option.WithTokenSource(delegatetokenSource))
//
// Note that this is not a standard OAuth flow, but rather uses Google Cloud
// IAMCredentials API to exchange one oauth token for an impersonated account
// see: https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken
func DelegateTokenSource(ctx context.Context, rootSource oauth2.TokenSource,
        principal string, lifetime time.Duration, delegates []string,
        newScopes []string) (oauth2.TokenSource, error) {

        reEmail := regexp.MustCompile(emailRegex)
        scopePrefix := "https://www.googleapis.com/auth/"

        if rootSource == nil {
                return nil, fmt.Errorf("oauth2/google:  rootSource cannot be nil")
        }
        if !reEmail.MatchString(principal) {
                return nil, fmt.Errorf("oauth2/google:  principal must be a serviceAccount email address")
        }
        if lifetime > (3600 * time.Second) {
                return nil, fmt.Errorf("oauth2/google:  lifetime must be less than or equal to 3600 seconds")
        }
        for _, d := range delegates {
                if !reEmail.MatchString(d) {
                        return nil, fmt.Errorf("oauth2/google:  delegates must be a serviceAccount email address: %v", d)
                }
        }
        for _, s := range newScopes {
                if !strings.HasPrefix(s, scopePrefix) {
                        return nil, fmt.Errorf("oauth2/google:  scopes must be a Google Auth scope url: %v", s)
                }
        }

        return &delegateTokenSource{
                ctx:        ctx,
                rootSource: rootSource,
                principal:  principal,
                lifetime:   lifetime,
                delegates:  delegates,
                newScopes:  newScopes,
        }, nil
}

type delegateTokenSource struct {
        ctx        context.Context
        rootSource oauth2.TokenSource
        principal  string
        lifetime   time.Duration
        delegates  []string
        newScopes  []string
}

func (ts *delegateTokenSource) Token() (*oauth2.Token, error) {

        mu.Lock()
        defer mu.Unlock()

        if tok.Valid() {
                return tok, nil
        }
        client := oauth2.NewClient(ts.ctx, ts.rootSource)

        service, err := iamcredentials.New(client)
        if err != nil {
                return nil, fmt.Errorf("oauth2/google: Error creating IAMCredentials: %v", err)
        }
        name := "projects/-/serviceAccounts/" + ts.principal
        tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
                Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
                Delegates: ts.delegates,
                Scope:     ts.newScopes,
        }
        at, err := service.Projects.ServiceAccounts.GenerateAccessToken(name, tokenRequest).Do()
        if err != nil {
                return nil, fmt.Errorf("oauth2/google: Error calling iamcredentials.GenerateAccessToken: %v", err)
        }

        expireAt, err := time.Parse(time.RFC3339, at.ExpireTime)
        if err != nil {
                return nil, fmt.Errorf("oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
        }

        tok = &oauth2.Token{
                AccessToken: at.AccessToken,
                Expiry:      expireAt,
        }

        return tok, nil
}
