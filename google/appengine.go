// +build appengine

package google

import (
	"github.com/golang/oauth2"

	"appengine"
	"appengine/urlfetch"
)

// AppEngineConfig represents a configuration for an
// App Engine application's Google service account.
type AppEngineConfig struct {
	// Default transport to be used while constructing
	// oauth2.Transport instances from this configuration.
	Transport *urlfetch.Transport
	context   appengine.Context
	scopes    []string
}

// NewAppEngineConfig creates a new AppEngineConfig for the
// provided auth scopes.
func NewAppEngineConfig(context appengine.Context, scopes []string) *AppEngineConfig {
	return &AppEngineConfig{context: context, scopes: scopes}
}

// NewTransport returns a transport that authorizes
// the requests with the application's service account.
func (c *AppEngineConfig) NewTransport() *oauth2.Transport {
	if c.Transport != nil {
		return oauth2.NewTransport(c.Transport, c, nil)
	}
	transport := &urlfetch.Transport{
		Context:                       c.context,
		Deadline:                      0,
		AllowInvalidServerCertificate: false,
	}
	return oauth2.NewTransport(transport, c, nil)
}

// FetchToken fetches a new access token for the provided scopes.
func (c *AppEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	token, expiry, err := appengine.AccessToken(c.context, c.scopes...)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token,
		Expiry:      expiry,
	}, nil
}
