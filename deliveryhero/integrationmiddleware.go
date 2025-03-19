package deliveryhero

import (
	"context"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
)

// DeliveryHeroConfig is the configuration of DeliveryHero.
// https://integration-middleware.stg.restaurant-partners.com/apidocs/pos-middleware-api#tag/Auth/operation/Login
type Config struct {
	// UserName is the application's username.
	UserName string

	// Password is the application's password.
	Password string

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string

	// AuthStyle optionally specifies how the endpoint wants the
	// UserName & Password secret sent. The zero value means to
	// auto-detect.
	AuthStyle oauth2.AuthStyle
}

// Token uses client credentials to retrieve a token.
//
// The provided context optionally controls which HTTP client is used. See the oauth2.HTTPClient variable.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	return c.TokenSource(ctx).Token()
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary.
//
// The provided context optionally controls which HTTP client
// is returned. See the oauth2.HTTPClient variable.
//
// The returned Client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// UserName and Password.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// Token refreshes the token by using a new client credentials request.
// tokens received this way do not include a refresh token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	v := url.Values{
		"username":   {c.conf.UserName},
		"password":   {c.conf.Password},
		"grant_type": {"client_credentials"},
	}

	tk, err := internal.RetrieveToken(c.ctx, "", "", c.conf.TokenURL, v, internal.AuthStyle(c.conf.AuthStyle))
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*oauth2.RetrieveError)(rErr)
		}
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken: tk.AccessToken,
		TokenType:   tk.TokenType,
		Expiry:      tk.Expiry,
	}
	return t.WithExtra(tk.Raw), nil
}
