// +build appengine

package google

import (
	"strings"

	"appengine"
	"github.com/golang/oauth2"
)

type AppEngineConfig struct {
	context appengine.Context
	scopes  []string
	cache   oauth2.Cache
}

func NewAppEngineConfig(context appengine.Context, scopes []string) *AppEngineConfig {
	return &AppEngineConfig{context: context, scopes: scopes}
}

func (c *AppEngineConfig) NewTransport() oauth2.Transport {
	return oauth2.NewAuthorizedTransport(c, nil)
}

func (c *AppEngineConfig) NewTransportWithCache(cache oauth2.Cache) (oauth2.Transport, error) {
	token, err := cache.Read()
	if err != nil {
		return nil, err
	}
	c.cache = cache
	return oauth2.NewAuthorizedTransport(c, token), nil
}

func (c *AppEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	token, expiry, err := appengine.AccessToken(c.context, strings.Join(c.scopes, " "))
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token,
		Expiry:      expiry,
	}, nil
}

func (c *AppEngineConfig) Cache() oauth2.Cache {
	return c.cache
}
