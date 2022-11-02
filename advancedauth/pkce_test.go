package advancedauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth/pkce"
)

func TestPKCE_AuthorizationCodeFlow(t *testing.T) {
	tcs := []struct {
		title     string
		config    oauth2.Config
		publicKey interface{}
	}{
		{
			title: "pkce with client auth",
			config: oauth2.Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				Endpoint: oauth2.Endpoint{
					AuthStyle: oauth2.AuthStyleInParams,
				},
				Scopes: []string{"scope1", "scope2"},
			},
		},
		{
			title: "pkce without client auth",
			config: oauth2.Config{
				ClientID: "CLIENT_ID",
				Endpoint: oauth2.Endpoint{
					AuthStyle: oauth2.AuthStyleInParams,
				},
				Scopes: []string{"scope1", "scope2"},
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {

			p, _ := pkce.New()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectURL(tt, r, "/token")
				expectHeader(tt, r, "Content-Type", "application/x-www-form-urlencoded")
				expectFormParam(tt, r, "client_id", "CLIENT_ID")
				if tc.config.ClientSecret != "" {
					expectFormParam(tt, r, "client_secret", "CLIENT_SECRET")
				}
				expectFormParam(tt, r, "code", "exchange-code")
				expectFormParam(tt, r, "grant_type", "authorization_code")
				expectFormParam(tt, r, "code_verifier", p.Verifier)
				expectFormParam(tt, r, "code_challenge_method", string(p.Method))
				expectFormParam(tt, r, "scope", "")

				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err := w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
				if err != nil {
					tt.Errorf("could not write body")
				}
			}))
			defer ts.Close()
			conf := tc.config
			conf.Endpoint.TokenURL = ts.URL + "/token"

			expectedAuthCodeURL := fmt.Sprintf(
				"?client_id=%s&code_challenge=%s&code_challenge_method=%s&response_type=code&scope=%s&state=state",
				tc.config.ClientID, p.Challenge, p.Method, strings.Join(tc.config.Scopes, "+"),
			)

			url := conf.AuthCodeURL("state", p.ChallengeOpt(), p.MethodOpt())
			expectStringsEqual(tt, expectedAuthCodeURL, url)

			url = conf.AuthCodeURL("state", p.AuthCodeURLOpts()...)
			expectStringsEqual(tt, expectedAuthCodeURL, url)

			tok, err := conf.Exchange(context.Background(), "exchange-code", p.ExchangeOpts()...)
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

func TestPKCE(t *testing.T) {
	tcs := []struct {
		title       string
		method      pkce.Method
		verifierLen int
		error       bool
	}{
		{
			title: "simple",
		},
		{
			title:       "plain",
			method:      pkce.S512,
			verifierLen: 50,
		},
		{
			title:  "S512",
			method: pkce.S512,
		},
		{
			title:       "invalid method",
			method:      "some random stuff",
			verifierLen: 50,
			error:       true,
		},
		{
			title:       "verifier too short",
			method:      "S256",
			verifierLen: 20,
			error:       true,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			var (
				p   pkce.PKCE
				err error
			)

			if tc.method != "" && tc.verifierLen != 0 {
				p, err = pkce.NewWithMethodVerifierLength(tc.method, tc.verifierLen)
			} else {
				p, err = pkce.New()
				expectStringsEqual(tt, "S256", string(p.Method))
			}

			if err != nil && !tc.error {
				tt.Fatalf("could not generate PKCE, got %+v", err)
			} else if err == nil && tc.error {
				tt.Fatalf("expected error, got nil")
			} else if err == nil {
				if tc.verifierLen == 0 {
					if len(p.Verifier) != 64 {
						tt.Fatalf("expected verifier of length 64")
					}
				} else if len(p.Verifier) != tc.verifierLen {
					tt.Fatalf("expected verifier of length %d", tc.verifierLen)
				}

				if tc.method == pkce.Plain {
					expectStringsEqual(tt, p.Verifier, p.Challenge)
				}
			}
		})
	}
}
