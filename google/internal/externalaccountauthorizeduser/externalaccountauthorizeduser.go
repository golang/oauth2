package externalaccountauthorizeduser

import (
	"context"
	"errors"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/internal/sts_exchange"
)

// now aliases time.Now for testing
var now = func() time.Time {
	return time.Now().UTC()
}

var tokenValid = func(token oauth2.Token) bool {
	return token.Valid()
}

type Config struct {
	Audience       string
	RefreshToken   string
	TokenURL       string
	TokenInfoURL   string
	ClientID       string
	ClientSecret   string
	Token          string
	Expiry         time.Time
	RevokeURL      string
	QuotaProjectID string
	Scopes         []string
}

func (c *Config) canRefresh() bool {
	return c.ClientID != "" && c.ClientSecret != "" && c.RefreshToken != "" && c.TokenURL != ""
}

func (c *Config) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	var token oauth2.Token
	if c.Token != "" && !c.Expiry.IsZero() {
		token = oauth2.Token{
			AccessToken: c.Token,
			Expiry:      c.Expiry,
			TokenType:   "Bearer",
		}
	}
	if !tokenValid(token) && !c.canRefresh() {
		return nil, errors.New("oauth2/google: Token should be created with fields to make it valid (`token` and `expiry`), or fields to allow it to refresh (`refresh_token`, `token_url`, `client_id`, `client_secret`).")
	}

	ts := tokenSource{
		ctx:  ctx,
		conf: c,
	}

	return oauth2.ReuseTokenSource(&token, ts), nil
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

func (ts tokenSource) Token() (*oauth2.Token, error) {
	conf := ts.conf
	if !conf.canRefresh() {
		return nil, errors.New("oauth2/google: The credentials do not contain the necessary fields need to refresh the access token. You must specify refresh_token, token_url, client_id, and client_secret.")
	}

	clientAuth := sts_exchange.ClientAuthentication{
		AuthStyle:    oauth2.AuthStyleInHeader,
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
	}

	stsResponse, err := sts_exchange.RefreshToken(ts.ctx, conf.TokenURL, conf.RefreshToken, clientAuth, nil)
	if err != nil {
		return nil, err
	}
	if stsResponse.ExpiresIn < 0 {
		return nil, errors.New("oauth2/google: got invalid expiry from security token service")
	}

	if stsResponse.RefreshToken != "" {
		conf.RefreshToken = stsResponse.RefreshToken
	}

	token := &oauth2.Token{
		AccessToken: stsResponse.AccessToken,
		Expiry:      now().Add(time.Duration(stsResponse.ExpiresIn) * time.Second),
		TokenType:   "Bearer",
	}
	return token, nil
}
