package externalaccount

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// The configuration for fetching tokens with external credentials.
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

	Scopes []string
}

// Returns an external account TokenSource. This is to be called by package google to construct a google.Credentials.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	ts := tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, ts)
}

//Subject token file types
const (
	fileTypeText = "text"
	fileTypeJSON = "json"
)

type format struct {
	// Either "text" or "json".  When not provided "text" type is assumed.
	Type string `json:"type"`
	// Only required for JSON.
	// This would be "access_token" for azure.
	SubjectTokenFieldName string `json:"subject_token_field_name"`
}

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

func (cs CredentialSource) instance() baseCredentialSource {
	if cs.EnvironmentID == "awsX" {
		return nil
		//return awsCredentialSource{EnvironmentID:cs.EnvironmentID, RegionURL:cs.RegionURL, RegionalCredVerificationURL: cs.RegionalCredVerificationURL, CredVerificationURL:cs.CredVerificationURL}
	} else if cs.File == "internalTestingFile" {
		return testCredentialSource{}
	} else if cs.File != "" {
		return fileCredentialSource{File: cs.File}
	} else if cs.URL != "" {
		//return urlCredentialSource{URL:cs.URL, Headers:cs.Headers}
		return nil
	} else {
		return nil
	}
}

type baseCredentialSource interface {
	retrieveSubjectToken(c *Config) (string, error)
}

// tokenSource is the source that handles 3PI credentials.
type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// This method is implemented so that tokenSource conforms to oauth2.TokenSource.
func (ts tokenSource) Token() (*oauth2.Token, error) {
	conf := ts.conf

	subjectToken, err := conf.CredentialSource.instance().retrieveSubjectToken(conf)
	if err != nil {
		return &oauth2.Token{}, err
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
		fmt.Errorf("oauth2/google: %s", err.Error())
		return &oauth2.Token{}, err
	}

	accessToken := &oauth2.Token{
		AccessToken: stsResp.AccessToken,
		TokenType:   stsResp.TokenType,
	}
	if stsResp.ExpiresIn < 0 {
		fmt.Errorf("google/oauth2: got invalid expiry from security token service")
		// REVIEWERS: Should I return the Token that I actually got back here so that people could inspect the result even with a improper ExpiresIn response?
		// Or is it more appropriate to still return an empty token: &oauth2.Token{} so that anybody who checks for an empty token as a sign of failure doesn't get confused.
		return accessToken, nil
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
