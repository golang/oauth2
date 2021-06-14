package downscope_test

import (
	"context"
	"log"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/downscope"
)

func ExampleNewTokenSource() {
	ctx := context.Background()
	// Initializes an accessBoundary with one Rule
	accessBoundary := []downscope.AccessBoundaryRule{
		downscope.AccessBoundaryRule{
			AvailableResource:    "//storage.googleapis.com/projects/_/buckets/foo",
			AvailablePermissions: []string{"inRole:roles/storage.objectViewer"},
		},
	}

	var rootSource oauth2.TokenSource
	// This Source can be initialized using Application Default Credentials as follows:

	// rootSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")

	myTokenSource, err := downscope.NewTokenSource(ctx, downscope.DownscopingConfig{RootSource: rootSource, Rules: accessBoundary})
	//myTokenSource, err := NewSource(rootSource, myBoundary)
	if err != nil {
		log.Fatalf("failed to generate downscoped token source: %v", err)
	}
	_ = myTokenSource
	// You can now use the token held in myTokenSource to make
	// Google Cloud Storage calls, as follows:

	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
}

type localTokenSource struct {
	tokenBrokerURL       string
	tokenSourceForBroker oauth2.TokenSource
}

func (lts localTokenSource) Token() (*oauth2.Token, error) {
	// Make a call to a remote token broker, which runs downscope.NewTokenSource
	// to generate a downscoped version of a token it holds.  Return
	var tok oauth2.Token
	return &tok, nil
}

// ExampleRefreshableToken provices a sample of how a token consumer would
// construct a refreshable token by wrapping a method that requests a
// downscoped token from a token broker in an oauth2.ReuseTokenSource
func ExampleRefreshableToken() {
	var myCredentials oauth2.TokenSource
	// This Source contains the credentials that the token consumer uses to
	// authenticate itself to the token broker from which it is requesting
	// a downscoped token.
	myTokenSource := localTokenSource{
		tokenBrokerURL:       "www.foo.bar",
		tokenSourceForBroker: myCredentials,
	}

	downscopedToken := oauth2.ReuseTokenSource(nil, myTokenSource)
	// downscopedToken can now be used as a refreshable token for Google Cloud Storage calls
	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
	_ = downscopedToken
}
