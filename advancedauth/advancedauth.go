package advancedauth

import (
	"context"
	"net/url"
)

type Algorithm string

const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"

	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

type AuthStyle int

const (
	// AuthStylePrivateKeyJWT sends a JWT assertion
	// signed using the private key
	// described in OpenID Connect Core
	AuthStylePrivateKeyJWT AuthStyle = 3

	// AuthStyleTLS
	AuthStyleTLS AuthStyle = 4
)

type Config struct {
	AuthStyle      AuthStyle
	ClientID       string
	PrivateKeyAuth PrivateKeyAuth
	TLSAuth        TLSAuth
	TokenURL       string
}

func ExtendUrlValues(v url.Values, c Config) error {
	if c.AuthStyle == AuthStylePrivateKeyJWT {
		jwtVals, err := privateKeyJWTAssertionVals(c)
		if err != nil {
			return err
		}

		for key, vals := range jwtVals {
			for _, val := range vals {
				v.Set(key, val)
			}
		}
	}
	if c.AuthStyle == AuthStyleTLS {
		v.Set("client_id", c.ClientID)
	}
	return nil
}

func ExtendContext(ctx context.Context, httpClientContextKey interface{}, c Config) (context.Context, error) {
	if c.AuthStyle == AuthStyleTLS {
		return extendContextWithTLSClient(ctx, httpClientContextKey, c)
	}
	return ctx, nil
}
