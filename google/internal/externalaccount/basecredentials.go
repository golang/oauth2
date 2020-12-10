// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// Config stores the configuration for fetching tokens with external credentials.
type Config struct {
	Audience                       string
	SubjectTokenType               string
	TokenURL                       string
	TokenInfoURL                   string
	ServiceAccountImpersonationURL string
	ClientSecret                   string
	ClientID                       string
	CredentialSource               CredentialSource
	QuotaProjectID                 string
	Scopes                         []string
}

// TokenSource Returns an external account TokenSource struct. This is to be called by package google to construct a google.Credentials.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	ts := tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, ts)
}

// Subject token file types
const (
	fileTypeText = "text"
	fileTypeJSON = "json"
)

type format struct {
	// Either "text" or "json".  When not provided "text" type is assumed.
	Type string `json:"type"`
	// SubjectTokenFieldName is only required for JSON format.
	// This would be "access_token" for azure.
	SubjectTokenFieldName string `json:"subject_token_field_name"`
}

// CredentialSource stores the information necessary to retrieve the credentials for the STS exchange
type CredentialSource struct {
	File string `json:"file"`

	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`

	EnvironmentID               string `json:"environment_id"`
	RegionURL                   string `json:"region_url"`
	RegionalCredVerificationURL string `json:"regional_cred_verification_url"`
	CredVerificationURL         string `json:"cred_verification_url"`
	Format                      format `json:"format"`
}

// instance determines the type of CredentialSource needed
func (cs CredentialSource) instance() baseCredentialSource {
	if cs.EnvironmentID == "awsX" {
		return nil
	} else if cs.File == "internalTestingFile" {
		return testCredentialSource{}
	} else if cs.File != "" {
		return fileCredentialSource{File: cs.File}
	} else if cs.URL != "" {
		return nil
	}
	return nil
}

type baseCredentialSource interface {
	retrieveSubjectToken(c *Config) (string, error)
}

// tokenSource is the source that handles external credentials.
type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// Token allows tokenSource to conform to the oauth2.TokenSource interface.
func (ts tokenSource) Token() (*oauth2.Token, error) {
	conf := ts.conf

	subjectToken, err := conf.CredentialSource.instance().retrieveSubjectToken(conf)
	if err != nil {
		return nil, err
	}
	stsRequest := STSTokenExchangeRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Audience:           conf.Audience,
		Scope:              conf.Scopes,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectToken:       subjectToken,
		SubjectTokenType:   conf.SubjectTokenType,
	}
	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")
	clientAuth := ClientAuthentication{
		AuthStyle:    oauth2.AuthStyleInHeader,
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
	}
	stsResp, err := ExchangeToken(ts.ctx, conf.TokenURL, &stsRequest, clientAuth, header, nil)
	if err != nil {
		return nil, err
	}

	accessToken := &oauth2.Token{
		AccessToken: stsResp.AccessToken,
		TokenType:   stsResp.TokenType,
	}
	if stsResp.ExpiresIn < 0 {
		return nil, fmt.Errorf("google/oauth2: got invalid expiry from security token service")
	} else if stsResp.ExpiresIn > 0 {
		accessToken.Expiry = time.Now().Add(time.Duration(stsResp.ExpiresIn) * time.Second)
	}

	if stsResp.RefreshToken != "" {
		accessToken.RefreshToken = stsResp.RefreshToken
	}

	return accessToken, nil
}

// NOTE: this method doesn't exist yet. It is being investigated to add this method to oauth2.TokenSource.
//func (ts tokenSource) TokenInfo() (*oauth2.TokenInfo, error)

// testCredentialSource is only used for testing, but must be defined here in order to avoid undefined errors when testing.
type testCredentialSource struct {
	File string
}

func (cs testCredentialSource) retrieveSubjectToken(c *Config) (string, error) {
	return "Sample.Subject.Token", nil
}
