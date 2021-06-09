package downscoped

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

const (
	identityBindingEndpoint = "https://sts.googleapis.com/v1beta/token"
)

// Defines an upper bound of permissions available for a GCP credential for one or more resources
type AccessBoundary struct {
	// One or more AccessBoundaryRules are required to define permissions for the new downscoped token
	AccessBoundaryRules []AccessBoundaryRule `json:"accessBoundaryRules"`
}

type AvailabilityCondition struct {
	Title       string `json:"title,omitempty"`
	Expression  string `json:"expression"`
	Description string `json:"description,omitempty"`
}

type AccessBoundaryRule struct {
	AvailableResource    string                 `json:"availableResource"`
	AvailablePermissions []string               `json:"availablePermissions"`
	Condition            *AvailabilityCondition `json:"availabilityCondition,omitempty"`
}

type downscopedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

type DownscopingConfig struct {
	RootSource               oauth2.TokenSource
	CredentialAccessBoundary AccessBoundary
}

func downscopedTokenWithEndpoint(ctx context.Context, config DownscopingConfig, endpoint string) (oauth2.TokenSource, error) {
	if config.RootSource == nil {
		return nil, fmt.Errorf("oauth2/google/downscoped: rootTokenSource cannot be nil")
	}
	if len(config.CredentialAccessBoundary.AccessBoundaryRules) == 0 {
		return nil, fmt.Errorf("oauth2/google/downscoped: length of AccessBoundaryRules must be at least 1")
	}

	downscopedOptions := struct {
		Boundary AccessBoundary `json:"accessBoundary"`
	}{
		Boundary: config.CredentialAccessBoundary,
	}

	tok, err := config.RootSource.Token()
	if err != nil {
		return nil, fmt.Errorf("oauth2/google/downscoped: unable to refresh root token %v", err)
	}

	b, err := json.Marshal(downscopedOptions)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google/downscoped: Unable to marshall AccessBoundary payload %v", err)
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("subject_token", tok.AccessToken)
	form.Add("options", url.QueryEscape(string(b)))

	myClient := oauth2.NewClient(ctx, nil)
	resp, err := myClient.PostForm(endpoint, form)
	if err != nil {
		return nil, fmt.Errorf("unable to generate POST Request %v", err)
	}
	defer resp.Body.Close()

	var tresp downscopedTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tresp)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to exchange token %v", tresp)
	}

	// an exchanged token that is derived from a service account (2LO) has an expired_in value
	// a token derived from a users token (3LO) does not.
	// The following code uses the time remaining on rootToken for a user as the value for the
	// derived token's lifetime
	var expiry_time time.Time
	if tresp.ExpiresIn > 0 {
		expiry_time = time.Now().Add(time.Duration(time.Duration(tresp.ExpiresIn) * time.Second))
	} else {
		expiry_time = tok.Expiry
	}

	newToken := &oauth2.Token{
		AccessToken: tresp.AccessToken,
		TokenType:   tresp.TokenType,
		Expiry:      expiry_time,
	}
	return oauth2.StaticTokenSource(newToken), nil
}

func NewDownscopedTokenSource(ctx context.Context, config DownscopingConfig) (oauth2.TokenSource, error) {
	return downscopedTokenWithEndpoint(ctx, config, identityBindingEndpoint)
}
