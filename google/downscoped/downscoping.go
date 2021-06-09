package downscoped

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const (
	IDENTITY_BINDING_ENDPOINT = "https://sts.googleapis.com/v1beta/token"
)

// Defines an upper bound of permissions available for a GCP credential for one or more resources
type AccessBoundary struct {
	AccessBoundaryRules []AccessBoundaryRule `json:"accessBoundaryRules"`
}

func NewAccessBoundary() AccessBoundary {
	return AccessBoundary{make([]AccessBoundaryRule, 0)}
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

type DownScopedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

type DownscopingConfig struct {
	RootSource               oauth2.TokenSource
	CredentialAccessBoundary AccessBoundary
}

func DownscopedTokenWithEndpoint(config DownscopingConfig, endpoint string) (oauth2.TokenSource, error) {
	if config.RootSource == nil {
		return nil, fmt.Errorf("oauth2/google: rootTokenSource cannot be nil")
	}
	if len(config.CredentialAccessBoundary.AccessBoundaryRules) == 0 {
		return nil, fmt.Errorf("oauth2/google: length of AccessBoundaryRules must be at least 1")
	}

	downscopedOptions := struct {
		Boundary AccessBoundary `json:"accessBoundary"`
	}{
		Boundary: config.CredentialAccessBoundary,
	}

	tok, err := config.RootSource.Token()
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to refresh root token %v", err)
	}

	b, err := json.Marshal(downscopedOptions) // TODO: make sure that this marshals properly!
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: Unable to marshall AccessBoundary payload %v", err)
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("subject_token", tok.AccessToken)
	form.Add("options", url.QueryEscape(string(b)))

	resp, err := http.PostForm(endpoint, form)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("unable to generate POST Request %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unable to exchange token %v", string(bodyBytes))
	}

	tresp := DownScopedTokenResponse{}
	json.NewDecoder(resp.Body).Decode(&tresp)

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

func NewDownscopedTokenSource(config DownscopingConfig) (oauth2.TokenSource, error) {
	return DownscopedTokenWithEndpoint(config, IDENTITY_BINDING_ENDPOINT)
}
