package advancedauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
	"github.com/golang-jwt/jwt/v4"
)

const (
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDYRpq7yP3IaRxFjD9i1VWAFMHgLikJgGQaScg5S9XS3INwYz+E
ZtXrg6++HKyHjqEUeKT+2IZHSJPhOHdKaxh7KCci31MXHtWSG8xMaikKWyLPXjmU
kqONQHOD7XvECqQ8KGkrZ5BTIkVa7KA6aXlYoc3zQpOfbf+wx3/57uuDQQIDAQAB
AoGADKfdCB4T07Vq5Rr23pazQSJ10eOBnT+5G9yzbb7lTUiAHISCRAIshHKZRxuw
cOJExMjmhs8u1F8H4EcIm/82WGsMegCLrS8Y1zW2goiNqIh4QBGHudgvmrXQFz+T
9euhREf4gq7npIHW/ahjCMeEc2Yom4wQC6QJ0bOUu/hiqm0CQQDzIEpFZQnYYMzn
99lk4Qnxh1l0UzTJNNKVidEXi3iHam2ztTkE5mIWlZKHvg5DHzOmvzPKYzFS2YS+
0RACf2/PAkEA47pX1Qc8axoqTBSELA1i3ZKc+qs0mmh2FXcDB2OcpUH00sXLCjGO
r3d57vNRKUYfu7VAQliis8iq5+DPA4sP7wJBAOyLhxd7VZfbnqE2qKGYvcbrzCH8
bogwx45Ml03UGcGO0Asfj8lvqRGWFwnQ5SlzKxraPrZzyeJ01c2dtHjpqksCQCj1
G9Txnzk4FIFoczklEzH8q4UeA7D9trc3l3Ddxo+mZC0Aa/siXKJMX77NPjypIw30
lGEaZfDl128q7LCbczsCQGIBBN0TAwxfYstKeD7g7GXG8yD10LlmB3FCBdQjoBaW
tfeljbt+hNJU/3NIvDhYujEfG2d9cmBZulMRY7gh40Y=
-----END RSA PRIVATE KEY-----`

	publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYRpq7yP3IaRxFjD9i1VWAFMHg
LikJgGQaScg5S9XS3INwYz+EZtXrg6++HKyHjqEUeKT+2IZHSJPhOHdKaxh7KCci
31MXHtWSG8xMaikKWyLPXjmUkqONQHOD7XvECqQ8KGkrZ5BTIkVa7KA6aXlYoc3z
QpOfbf+wx3/57uuDQQIDAQAB
-----END PUBLIC KEY-----`

	privateECDSAKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMlmB8ys8+Sp4b0zSzghVD9q9GtljXTwI58f6sGJoFRQoAoGCCqGSM49
AwEHoUQDQgAEO1sWioJjxNghnKRcH1eHMCTreC2FvVWVDgE2dqe84TeXtbkAUosr
9EdTaTI96qG8xnCEKg3QLnCRuJj54SqpSQ==
-----END EC PRIVATE KEY-----`

	publicECDSAKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO1sWioJjxNghnKRcH1eHMCTreC2F
vVWVDgE2dqe84TeXtbkAUosr9EdTaTI96qG8xnCEKg3QLnCRuJj54SqpSQ==
-----END PUBLIC KEY-----`
)

func TestPrivateKeyJWT_ClientCredentials(t *testing.T) {
	rsaPubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		t.Error("could not parse rsa public key")
	}
	ecdsaPubKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicECDSAKey))
	if err != nil {
		t.Error("could not parse ecdsa public key")
	}
	tcs := []struct {
		title     string
		config    clientcredentials.Config
		publicKey interface{}
	}{
		{
			title: "RSA",
			config: clientcredentials.Config{
				ClientID:  "CLIENT_ID",
				AuthStyle: oauth2.AuthStylePrivateKeyJWT,
				PrivateKeyAuth: advancedauth.PrivateKeyAuth{
					Key: privateKey,
				},
				Scopes:         []string{"scope1", "scope2"},
				EndpointParams: url.Values{"audience": {"audience1"}},
			},
			publicKey: rsaPubKey,
		},
		{
			title: "ECDSA",
			config: clientcredentials.Config{
				ClientID:  "CLIENT_ID",
				AuthStyle: oauth2.AuthStylePrivateKeyJWT,
				PrivateKeyAuth: advancedauth.PrivateKeyAuth{
					Key:       privateECDSAKey,
					Algorithm: "ES256",
				},
				Scopes:         []string{"scope1", "scope2"},
				EndpointParams: url.Values{"audience": {"audience1"}},
			},
			publicKey: ecdsaPubKey,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			var serverURL string

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectURL(tt, r, "/token")
				expectHeader(tt, r, "Authorization", "")
				expectHeader(tt, r, "Content-Type", "application/x-www-form-urlencoded")
				expectFormParam(tt, r, "client_id", "")
				expectFormParam(tt, r, "client_secret", "")
				expectFormParam(tt, r, "grant_type", "client_credentials")
				expectFormParam(tt, r, "scope", "scope1 scope2")
				expectFormParam(tt, r, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

				assertion := r.FormValue("client_assertion")
				claims := jwt.RegisteredClaims{}
				token, err := jwt.ParseWithClaims(assertion, &claims, func(token *jwt.Token) (interface{}, error) {
					return tc.publicKey, nil
				})
				if err != nil {
					tt.Errorf("could not parse assertion %+v", err)
				}
				if !token.Valid {
					tt.Error("invalid assertion token")
				}

				expectStringsEqual(tt, "CLIENT_ID", claims.Issuer)
				expectStringsEqual(tt, "CLIENT_ID", claims.Subject)

				// uuid v4 like
				expectTrue(tt, len(claims.ID) == 36)

				expectTrue(tt, time.Now().Unix() < claims.ExpiresAt.Unix())
				expectStringsEqual(tt, serverURL, claims.Audience[0])

				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err = w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
				if err != nil {
					tt.Errorf("could not write body")
				}
			}))
			serverURL = ts.URL
			defer ts.Close()
			conf := tc.config
			conf.TokenURL = serverURL + "/token"
			tok, err := conf.Token(context.Background())
			if err != nil {
				tt.Error(err)
			}
			expectAccessToken(tt, &oauth2.Token{
				AccessToken:  "90d64460d14870c08c81352a05dedd3465940a7c",
				TokenType:    "bearer",
				RefreshToken: "",
				Expiry:       time.Time{},
			}, tok)
		})
	}

}
