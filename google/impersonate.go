// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
        "context"
        "fmt"
        "sync"
        "time"

        "golang.org/x/oauth2"
        "google.golang.org/api/iamcredentials/v1"
)

var (
        mu  sync.Mutex
        tok *oauth2.Token
)

// ImpersonatedTokenSource allows a TokenSource issued to a user or
// service account to impersonate another.  The source project using
// ImpersonatedTokenSource must enable the "IAMCredentials" API.  Also, the
// target service account must grant the orginating principal the
// "Service Account Token Creator" IAM role:
// https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role
//
//  rootSource (TokenSource): The root TokenSource
//     used as to acquire the target identity TokenSource.
//     rootSource *must* include scopes that contains
//     "https://www.googleapis.com/auth/iam"
//     or
//     "https://www.googleapis.com/auth/cloud.platform"
//  targetPrincipal (string): The service account to impersonate.
//  targetScopes ([]string): Scopes to request during the
//     authorization grant.
//  delegates ([]string): The chained list of delegates required
//      to grant the final access_token.  If set, the sequence of
//      identities must have "Service Account Token Creator" capability
//      granted to the preceeding identity.  For example, if set to
//      [serviceAccountB, serviceAccountC], the source_credential
//      must have the Token Creator role on serviceAccountB.
//      serviceAccountB must have the Token Creator on serviceAccountC.
//      Finally, C must have Token Creator on target_principal.
//      If left unset, source_credential must have that role on
//      target_principal.
//  lifetime (time.Duration): Number of seconds the delegated credential should
//     be valid for (upto 3600).
//
// Usage:
//   targetPrincipal := "impersonated-account@project.iam.gserviceaccount.com"
//   lifetime := 30 * time.Second
//   delegates := []string{}
//   targetScopes := []string{storage.ScopeReadOnly}
//   rootTokenSource, err := google.DefaultTokenSource(ctx,
//           "https://www.googleapis.com/auth/iam")
//   impersonatedTokenSource, err := google.ImpersonatedTokenSource(ctx,
//       rootTokenSource,
//       targetPrincipal, lifetime, delegates, targetScopes)
//   storeageClient, _ = storage.NewClient(ctx,
//       option.WithTokenSource(impersonatedTokenSource))
//
// Note that this is not a standard OAuth flow, but rather uses Google Cloud
// IAMCredentials API to exchange one oauth token for an impersonated account
// see: https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken
func ImpersonatedTokenSource(ctx context.Context, rootSource oauth2.TokenSource,
        targetPrincipal string, lifetime time.Duration, delegates []string,
        targetScopes []string) (oauth2.TokenSource, error) {

        if rootSource == nil {
                return nil, fmt.Errorf("oauth2/google:  rootSource cannot be nil")
        }
        if lifetime > (3600 * time.Second) {
                return nil, fmt.Errorf("oauth2/google:  lifetime must be less than or equal to 3600 seconds")
        }

        return &impersonatedTokenSource{
                ctx:             ctx,
                rootSource:      rootSource,
                targetPrincipal: targetPrincipal,
                lifetime:        lifetime,
                delegates:       delegates,
                targetScopes:    targetScopes,
        }, nil
}

type impersonatedTokenSource struct {
        ctx             context.Context
        rootSource      oauth2.TokenSource
        targetPrincipal string
        lifetime        time.Duration
        delegates       []string
        targetScopes    []string
}

func (ts *impersonatedTokenSource) Token() (*oauth2.Token, error) {

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
        name := fmt.Sprintf("projects/-/serviceAccounts/%s", ts.targetPrincipal)
        tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
                Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
                Delegates: ts.delegates,
                Scope:     ts.targetScopes,
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
