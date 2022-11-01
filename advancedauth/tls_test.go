package advancedauth_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
)

const (
	key = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0uhESy4URdqwo
8Hbus5UjdxQom0zQj7jw4bcZ2Z4X0HLJbmbDZdwIaoOWfSjYu9VYPkE04/+KnBOh
XMpA8DfcyS+XVPPTAEFI7KH9RF7BTMjSxB32Huwz9hMHqiPxJx1R+dTSWSC61+GX
Dq+cLHGeQq4Cqxxf0nnGmgpnT26GtiG/QZzE0IdlxaK68BzFk3syNzVFE8Om6yzx
ET7L5/p6igFrj22enjbYimtcSuHM2k16n0MSipBL2v1scheifGN0P+po118IRuX2
mU8WH5Z8eyInWf857sNEHuFoCkuegJFVkzkuzxZz/F+cT1Znfq0x17ssnL9SFDk4
XpyNKTqPAgMBAAECggEAULaMq30zV8JNTxddtmuDnswut5fsLXUSnpnf4W6cOXyB
1040HO4f365aSFprZKg2tutOyeVNmkTsS3OabHgcKsG7PHXXUxPZFE2CZw8i1meJ
hP/LdcEHsokipJiq5qeWY6cVEkB16pxBhuorKa97qreS6WQsDut8MWNYZB1Iemaa
HjioQZ7SpUUUyr3XNuvoaPViymGou6DYLaIMg0zklOrfigu1Qb4XdtWtbdi3AWcr
dVNO/N8Y19pJGqpJZ0FlqT/G8es10prAJGPAy4O/RxsLEfOSlZHe1Oj5V63B5h6R
KPwzSRM03gqHG0qruhr2seQN2UvJSRJNz3a2q7siGQKBgQDsXvcohxXoVkv2yvq4
D9QmQxU3/zHPZhnFNpZ9p3a4AHvmTFyTErTPrZn+QW/l9VvyKGctezR9/SMTLmsQ
dz8Pnbqoukp2Vo/zNK1HEf3Iy5/lVZtd4ErfFCKpWYkNEXX43RQ2qvNt/XkkuIIg
mijoKxBfiwKD8sGB2B8owHCi6wKBgQDDvCglc1yPQ3dzEcaMOoABKWdH7Q72Xgjr
rpmO5lATn6kvcwgAjf/EEIGSQVjoY3zhOZ4J/eV7G6NTg9sRVhcWtkt1UtVv1BwE
Cg4P6W7hCg8GF8Egh/dYtarx19juZkXk5HNSe0PEgrpbjzdxx0s/2HE1JwziVa3q
qJFV4gd17QKBgQCS81dlctZD46LGg9rro6uZPgtrDNTCxA8xdIaLCBneuy5MNx02
smKG2r7qO3R92tSW8Fd1ByvTSBUOT8VwLzKdWso5K9gvShGkehNgI+dLdoyp31cA
PflORw5liqyR21Ekrw1qD03YC8XM9oiwDCdyb5N2Us31im6TcvGsPDfKkQKBgQCF
Ok0ZMKyP1xw29qJuUGNQZx4llvXYO6lWwkFDQwC+Wq6N3X5U4lJ04cdQBaq+gvk9
VDp+EpNgeC9zaQxzgGW2z94MvZUJyRZIqY9oxTrzciVHwGN0ARgbCYyRkJnXq0Vn
xxe3zK8T0ueF6rWSfFR74Jct1qauaCM41gQWsQLjAQKBgGfnF99nLe1iI4AZgLIQ
nYgCV65/bmbgX5gkMbDMxZzZYNWg15YuB5Ir+cf20pCwO5EmoLpn7KGpEeED4+/z
2PZrF4bcjmEhYT5O2Y1Wn1oB84uug9c+ME7yiU30g1FttURZuLtzUxASFP2o0l7r
zbSntKWbvm2qk39YKulrEnoh
-----END PRIVATE KEY-----`
	cert = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgUCFE+Ha5QgryApfoCjSX564o0JoGYIMA0GCSqGSIb3DQEBCwUAMCcx
CzAJBgNVBAYTAlVTMRgwFgYDVQQDDA9FeGFtcGxlLVJvb3QtQ0EwIBcNMjIxMDMx
MTgxODQ0WhgPMjA3NzA4MDMxODE4NDRaMG0xCzAJBgNVBAYTAlVTMRIwEAYDVQQI
DAlZb3VyU3RhdGUxETAPBgNVBAcMCFlvdXJDaXR5MR0wGwYDVQQKDBRFeGFtcGxl
LUNlcnRpZmljYXRlczEYMBYGA1UEAwwPbG9jYWxob3N0LmxvY2FsMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtLoREsuFEXasKPB27rOVI3cUKJtM0I+4
8OG3GdmeF9ByyW5mw2XcCGqDln0o2LvVWD5BNOP/ipwToVzKQPA33Mkvl1Tz0wBB
SOyh/URewUzI0sQd9h7sM/YTB6oj8ScdUfnU0lkgutfhlw6vnCxxnkKuAqscX9J5
xpoKZ09uhrYhv0GcxNCHZcWiuvAcxZN7Mjc1RRPDpuss8RE+y+f6eooBa49tnp42
2IprXErhzNpNep9DEoqQS9r9bHIXonxjdD/qaNdfCEbl9plPFh+WfHsiJ1n/Oe7D
RB7haApLnoCRVZM5Ls8Wc/xfnE9WZ36tMde7LJy/UhQ5OF6cjSk6jwIDAQABMA0G
CSqGSIb3DQEBCwUAA4IBAQCBeRGIRS2MljdbgExv5KEND4OhEj2kuuES1zzTQjgs
EO6G3RlFRU9dFz9WDsLSeegY/4Y8BwR6kA3IpmLVnfmn4odWHhLv+JCDo7TG+R6c
3JnHbLuimcMLnGVVdUzAxQz09bNxYhCqUEla/ji0GeSxg8j8ofxtE7qihODV5dQv
gx3Ef/WxZTy08hd8pKxA8dg/VzechNRngFpINXUnGsX699pSoPWfHQoyZprvWjE7
QDac6VgTzy/KPfaf9vi3MiXJyjJOuGO3+SL1PhR712qRGg9Y+kccNUlL4OfrLJpm
qobZlvUYUfAYcyJVtjas3vPoQHVCcbq7hdbso5FrLyPK
-----END CERTIFICATE-----`
)

func TestTLS_ClientCredentials(t *testing.T) {
	tcs := []struct {
		title  string
		config clientcredentials.Config
	}{
		{
			title: "TLS",
			config: clientcredentials.Config{
				ClientID:  "CLIENT_ID",
				AuthStyle: oauth2.AuthStyleTLS,
				TLSAuth: advancedauth.TLSAuth{
					Key:         key,
					Certificate: cert,
				},
				Scopes: []string{"scope1", "scope2"},
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			var serverURL string

			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectURL(tt, r, "/token")
				expectHeader(tt, r, "Authorization", "")
				expectHeader(tt, r, "Content-Type", "application/x-www-form-urlencoded")
				expectFormParam(tt, r, "client_id", "CLIENT_ID")
				expectFormParam(tt, r, "client_secret", "")
				expectFormParam(tt, r, "scope", "scope1 scope2")
				expectFormParam(tt, r, "grant_type", "client_credentials")

				cert := r.TLS.PeerCertificates[0]
				expectStringsEqual(tt, "Example-Root-CA", cert.Issuer.CommonName)

				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err := w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
				if err != nil {
					tt.Errorf("could not write body")
				}
			}))

			ts.TLS = &tls.Config{
				ClientAuth: tls.RequestClientCert,
			}

			ts.StartTLS()
			serverURL = ts.URL
			defer ts.Close()
			conf := tc.config
			conf.TokenURL = serverURL + "/token"

			_, err := conf.Token(context.Background())
			// context.Background() will fail as the server cert is not trusted
			// err == nil checks if there are no panics
			if err == nil {
				tt.Errorf("expected Token to fail with invalid server cert")
			}

			client := ts.Client()
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			tok, err := conf.Token(ctx)
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

func TestTLS_Exchange(t *testing.T) {
	tcs := []struct {
		title  string
		config oauth2.Config
	}{
		{
			title: "TLS",
			config: oauth2.Config{
				ClientID: "CLIENT_ID",
				Endpoint: oauth2.Endpoint{
					AuthStyle: oauth2.AuthStyleTLS,
				},
				TLSAuth: advancedauth.TLSAuth{
					Key:         key,
					Certificate: cert,
				},
				Scopes: []string{"scope1", "scope2"},
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			var serverURL string

			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectURL(tt, r, "/token")
				expectHeader(tt, r, "Authorization", "")
				expectHeader(tt, r, "Content-Type", "application/x-www-form-urlencoded")
				expectFormParam(tt, r, "client_id", "CLIENT_ID")
				expectFormParam(tt, r, "client_secret", "")
				expectFormParam(tt, r, "scope", "")
				expectFormParam(tt, r, "grant_type", "authorization_code")

				cert := r.TLS.PeerCertificates[0]
				expectStringsEqual(tt, "Example-Root-CA", cert.Issuer.CommonName)

				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err := w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
				if err != nil {
					tt.Errorf("could not write body")
				}
			}))

			ts.TLS = &tls.Config{
				ClientAuth: tls.RequestClientCert,
			}

			ts.StartTLS()
			serverURL = ts.URL
			defer ts.Close()
			conf := tc.config
			conf.Endpoint.TokenURL = serverURL + "/token"

			_, err := conf.Exchange(context.Background(), "random")
			// context.Background() will fail as the server cert is not trusted
			// err == nil checks if there are no panics
			if err == nil {
				tt.Errorf("expected Token to fail with invalid server cert")
			}

			client := ts.Client()
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			tok, err := conf.Exchange(ctx, "random")
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

type fakeRoundTripper struct{}

func (f *fakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestExtendContext(t *testing.T) {

	tcs := []struct {
		title           string
		ctx             context.Context
		errorExpected   bool
		auth            advancedauth.TLSAuth
		assertTransport func(ttt *testing.T, t *http.Transport)
	}{
		{
			title:         "background context",
			ctx:           context.Background(),
			errorExpected: false,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: cert,
			},
		},
		{
			title:         "invalid cert",
			ctx:           context.Background(),
			errorExpected: true,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: "random",
			},
		},
		{
			title:         "non *http.Client client",
			ctx:           context.WithValue(context.Background(), oauth2.HTTPClient, struct{}{}),
			errorExpected: true,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: cert,
			},
		},
		{
			title: "non *http.Transport transport",
			ctx: context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &fakeRoundTripper{},
			}),
			errorExpected: true,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: cert,
			},
		},
		{
			title:         "no transport configured",
			ctx:           context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{}),
			errorExpected: false,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: cert,
			},
		},
		{
			title: "configured transport",
			ctx: context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &http.Transport{
					IdleConnTimeout: 10 * time.Second,
				},
			}),
			errorExpected: false,
			auth: advancedauth.TLSAuth{
				Key:         key,
				Certificate: cert,
			},
			assertTransport: func(ttt *testing.T, tr *http.Transport) {
				expectTrue(ttt, tr.IdleConnTimeout == 10*time.Second)
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.title, func(tt *testing.T) {
			config := advancedauth.Config{
				AuthStyle: advancedauth.AuthStyleTLS,
				ClientID:  "random",
				TLSAuth:   tc.auth,
				TokenURL:  "random",
			}
			ctx, err := advancedauth.ExtendContext(tc.ctx, oauth2.HTTPClient, config)
			if tc.errorExpected && err == nil {
				tt.Errorf("expected error")
			} else if !tc.errorExpected && err != nil {
				tt.Fatalf("unexpected error %+v", err)
			} else if !tc.errorExpected && err == nil {
				c := ctx.Value(oauth2.HTTPClient)
				expectTrue(tt, c != nil)
				hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
				expectTrue(tt, ok)
				tr, ok := hc.Transport.(*http.Transport)
				expectTrue(tt, ok)
				certs := tr.TLSClientConfig.Certificates
				expectTrue(tt, len(certs) == 1)
				if tc.assertTransport != nil {
					tc.assertTransport(tt, tr)
				}
			}
		})
	}
}
