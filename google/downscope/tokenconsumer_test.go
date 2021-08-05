package downscope_test

import (
	"golang.org/x/oauth2"
)

type localTokenSource struct {
	requestedObject string
	brokerURL       string
}

func (localTokenSource) Token() (*oauth2.Token, error) {
	var remoteToken oauth2.Token
	// Retrieve remoteToken, an oauth2.Token, from token broker.
	return &remoteToken, nil
}

func Example() {
	// A token consumer should define their own tokenSource. In the Token() method,
	// it should send a query to a token broker requesting a downscoped token.
	// The token broker holds the root credential that is used to generate the
	// downscoped token.
	thisTokenSource := localTokenSource{
		requestedObject: "//storage.googleapis.com/projects/_/buckets/foo",
		brokerURL:       "yourURL.com/internal/broker",
	}

	// Wrap the TokenSource in an oauth2.ReuseTokenSource to enable automatic refreshing.
	refreshableTS := oauth2.ReuseTokenSource(nil, thisTokenSource)

	// You can now use the token source to access Google Cloud Storage resources as follows.

	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(refreshableTS))
	// bkt := storageClient.Bucket("foo")
	// obj := bkt.Object(objectName)
	// rc, err := obj.NewReader(ctx)
	// defer rc.Close()
	// data, err := ioutil.ReadAll(rc)
}
