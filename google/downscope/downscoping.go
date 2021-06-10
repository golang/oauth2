/*
Package downscope implements the ability to downwcope, or restrict, the
Identity and AccessManagement permissions that a short-lived Token
can use.  Please note that only Google Cloud Storage supports this feature.
 */
package downscope

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
	// One or more AccessBoundaryRules are required to define permissions
	// for the new downscoped token.  Each one defines an access (or set of accesses)
	// that the new token has to a given resource.
	AccessBoundaryRules []AccessBoundaryRule `json:"accessBoundaryRules"`
}

// An AvailabilityCondition restricts access to a given Resource.
type AvailabilityCondition struct {
	// A condition expression that specifies the Cloud Storage objects where
	// permissions are available. For further documentation, see
	// https://cloud.google.com/iam/docs/conditions-overview
	Expression  string `json:"expression"`
	// Optional. A short string that identifies the purpose of the condition.
	Title       string `json:"title,omitempty"`
	// Optional. Details about the purpose of the condition.
	Description string `json:"description,omitempty"`
}

// Sets the permissions (and optionally conditions) that the new
// token has on given resource.
type AccessBoundaryRule struct {
	// AvailableResource is the full resource name of the Cloud Storage bucket that the rule applies to.
	// Use the format //storage.googleapis.com/projects/_/buckets/bucket-name.
	AvailableResource    string                 `json:"availableResource"`
	// AvailablePermissions is a list that defines the upper bound on the available permissions
	// for the resource.  Each value is the identifier for an IAM predefined role or custom role,
	// with the prefix inRole:. For example: inRole:roles/storage.objectViewer.
	// Only the permissions in these roles will be available.
	AvailablePermissions []string               `json:"availablePermissions"`
	// An optional Condition that restricts the availability of permissions
	// to specific Cloud Storage objects.
	//
	// Use this field if you want to make permissions available for specific objects,
	// rather than all objects in a Cloud Storage bucket.
	Condition            *AvailabilityCondition `json:"availabilityCondition,omitempty"`
}

type downscopedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// Specifies the information necessary to request a downscoped token.
type DownscopingConfig struct {
	// RootSource is the TokenSource used to create the downscoped token.
	// The downscoped token therefore has some subset of the accesses of
	// the original RootSource.
	RootSource               oauth2.TokenSource
	// CredentialAccessBoundary defines the accesses held by the new
	// downscoped Token.
	CredentialAccessBoundary AccessBoundary
}

// downscopedTokenWithEndpoint is a helper function used for unit testing
// purposes, as it allows us to pass in a locally mocked endpoint.
func downscopedTokenWithEndpoint(ctx context.Context, config DownscopingConfig, endpoint string) (oauth2.TokenSource, error) {
	if config.RootSource == nil {
		return nil, fmt.Errorf("downscope: rootTokenSource cannot be nil")
	}
	if len(config.CredentialAccessBoundary.AccessBoundaryRules) == 0 {
		return nil, fmt.Errorf("downscope: length of AccessBoundaryRules must be at least 1")
	}
	for _, val := range config.CredentialAccessBoundary.AccessBoundaryRules {
		if val.AvailableResource == "" {
			return nil, fmt.Errorf("downscope: all rules must have a nonempty AvailableResource: %+v", val)
		}
		if len(val.AvailablePermissions) == 0 {
			return nil, fmt.Errorf("downscope: all rules must provide at least one permission: %+v", val)
		}
	}

	downscopedOptions := struct {
		Boundary AccessBoundary `json:"accessBoundary"`
	}{
		Boundary: config.CredentialAccessBoundary,
	}

	tok, err := config.RootSource.Token()
	if err != nil {
		return nil, fmt.Errorf("downscope: unable to obtain root token: %v", err)
	}

	b, err := json.Marshal(downscopedOptions)
	if err != nil {
		return nil, fmt.Errorf("downscope: Unable to marshall AccessBoundary payload %v", err)
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
		return nil, fmt.Errorf("unable to exchange token; %v", resp.StatusCode)
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

// NewTokenSource takes a root TokenSource and returns a downscoped TokenSource
// with a subset of the permissions held by the root source.  The
// CredentialAccessBoundary in the config defines the permissions held
// by the new TokenSource.  Do note that the returned TokenSource is
// an oauth2.StaticTokenSource.  If you wish to refresh this token automatically,
// then initialize a locally defined TokenSource struct with the Token held
// by the StaticTokenSource and wrap that TokenSource in an oauth2.ReuseTokenSource.
func NewTokenSource(ctx context.Context, config DownscopingConfig) (oauth2.TokenSource, error) {
	return downscopedTokenWithEndpoint(ctx, config, identityBindingEndpoint)
}
