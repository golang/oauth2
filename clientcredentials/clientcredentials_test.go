// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientcredentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

func newConf(serverURL string) *Config {
	return &Config{
		ClientID:       "CLIENT_ID",
		ClientSecret:   "CLIENT_SECRET",
		Scopes:         []string{"scope1", "scope2"},
		TokenURL:       serverURL + "/token",
		EndpointParams: url.Values{"audience": {"audience1"}},
	}
}

type mockTransport struct {
	rt func(req *http.Request) (resp *http.Response, err error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return t.rt(req)
}

func TestTokenSourceGrantTypeOverride(t *testing.T) {
	wantGrantType := "password"
	var gotGrantType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ioutil.ReadAll(r.Body) == %v, %v, want _, <nil>", body, err)
		}
		if err := r.Body.Close(); err != nil {
			t.Errorf("r.Body.Close() == %v, want <nil>", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("url.ParseQuery(%q) == %v, %v, want _, <nil>", body, values, err)
		}
		gotGrantType = values.Get("grant_type")
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
	}))
	config := &Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		Scopes:       []string{"scope"},
		TokenURL:     ts.URL + "/token",
		EndpointParams: url.Values{
			"grant_type": {wantGrantType},
		},
	}
	token, err := config.TokenSource(context.Background()).Token()
	if err != nil {
		t.Errorf("config.TokenSource(_).Token() == %v, %v, want !<nil>, <nil>", token, err)
	}
	if gotGrantType != wantGrantType {
		t.Errorf("grant_type == %q, want %q", gotGrantType, wantGrantType)
	}
}

func TestTokenRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("authenticate client request URL = %q; want %q", r.URL, "/token")
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type header = %q; want %q", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			r.Body.Close()
		}
		if err != nil {
			t.Errorf("failed reading request body: %s.", err)
		}
		if string(body) != "audience=audience1&grant_type=client_credentials&scope=scope1+scope2" {
			t.Errorf("payload = %q; want %q", string(body), "grant_type=client_credentials&scope=scope1+scope2")
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tok, err := conf.Token(context.Background())
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("token invalid. got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Access token = %q; want %q", tok.AccessToken, "90d64460d14870c08c81352a05dedd3465940a7c")
	}
	if tok.TokenType != "bearer" {
		t.Errorf("token type = %q; want %q", tok.TokenType, "bearer")
	}
}

var dummyPrivateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx4fm7dngEmOULNmAs1IGZ9Apfzh+BkaQ1dzkmbUgpcoghucE
DZRnAGd2aPyB6skGMXUytWQvNYav0WTR00wFtX1ohWTfv68HGXJ8QXCpyoSKSSFY
fuP9X36wBSkSX9J5DVgiuzD5VBdzUISSmapjKm+DcbRALjz6OUIPEWi1Tjl6p5RK
1w41qdbmt7E5/kGhKLDuT7+M83g4VWhgIvaAXtnhklDAggilPPa8ZJ1IFe31lNlr
k4DRk38nc6sEutdf3RL7QoH7FBusI7uXV03DC6dwN1kP4GE7bjJhcRb/7jYt7CQ9
/E9Exz3c0yAp0yrTg0Fwh+qxfH9dKwN52S7SBwIDAQABAoIBAQCaCs26K07WY5Jt
3a2Cw3y2gPrIgTCqX6hJs7O5ByEhXZ8nBwsWANBUe4vrGaajQHdLj5OKfsIDrOvn
2NI1MqflqeAbu/kR32q3tq8/Rl+PPiwUsW3E6Pcf1orGMSNCXxeducF2iySySzh3
nSIhCG5uwJDWI7a4+9KiieFgK1pt/Iv30q1SQS8IEntTfXYwANQrfKUVMmVF9aIK
6/WZE2yd5+q3wVVIJ6jsmTzoDCX6QQkkJICIYwCkglmVy5AeTckOVwcXL0jqw5Kf
5/soZJQwLEyBoQq7Kbpa26QHq+CJONetPP8Ssy8MJJXBT+u/bSseMb3Zsr5cr43e
DJOhwsThAoGBAPY6rPKl2NT/K7XfRCGm1sbWjUQyDShscwuWJ5+kD0yudnT/ZEJ1
M3+KS/iOOAoHDdEDi9crRvMl0UfNa8MAcDKHflzxg2jg/QI+fTBjPP5GOX0lkZ9g
z6VePoVoQw2gpPFVNPPTxKfk27tEzbaffvOLGBEih0Kb7HTINkW8rIlzAoGBAM9y
1yr+jvfS1cGFtNU+Gotoihw2eMKtIqR03Yn3n0PK1nVCDKqwdUqCypz4+ml6cxRK
J8+Pfdh7D+ZJd4LEG6Y4QRDLuv5OA700tUoSHxMSNn3q9As4+T3MUyYxWKvTeu3U
f2NWP9ePU0lV8ttk7YlpVRaPQmc1qwooBA/z/8AdAoGAW9x0HWqmRICWTBnpjyxx
QGlW9rQ9mHEtUotIaRSJ6K/F3cxSGUEkX1a3FRnp6kPLcckC6NlqdNgNBd6rb2rA
cPl/uSkZP42Als+9YMoFPU/xrrDPbUhu72EDrj3Bllnyb168jKLa4VBOccUvggxr
Dm08I1hgYgdN5huzs7y6GeUCgYEAj+AZJSOJ6o1aXS6rfV3mMRve9bQ9yt8jcKXw
5HhOCEmMtaSKfnOF1Ziih34Sxsb7O2428DiX0mV/YHtBnPsAJidL0SdLWIapBzeg
KHArByIRkwE6IvJvwpGMdaex1PIGhx5i/3VZL9qiq/ElT05PhIb+UXgoWMabCp84
OgxDK20CgYAeaFo8BdQ7FmVX2+EEejF+8xSge6WVLtkaon8bqcn6P0O8lLypoOhd
mJAYH8WU+UAy9pecUnDZj14LAGNVmYcse8HFX71MoshnvCTFEPVo4rZxIAGwMpeJ
5jgQ3slYLpqrGlcbLgUXBUgzEO684Wk/UV9DFPlHALVqCfXQ9dpJPg==
-----END RSA PRIVATE KEY-----`)

func TestTokenJWTRequest(t *testing.T) {
	var assertion string
	audience := "audience1"
	scopes := "scope1 scope2"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("authenticate client request URL = %q; want %q", r.URL, "/token")
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type header = %q; want %q", got, want)
		}
		err := r.ParseForm()
		if err != nil {
			t.Fatal(err)
		}

		if got, want := r.Form.Get("scope"), scopes; got != want {
			t.Errorf("scope = %q; want %q", got, want)
		}
		if got, want := r.Form.Get("audience"), audience; got != want {
			t.Errorf("audience = %q; want %q", got, want)
		}
		if got, want := r.Form.Get("grant_type"), "client_credentials"; got != want {
			t.Errorf("grant_type = %q; want %q", got, want)
		}
		expectedAssertionType := "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		if got, want := r.Form.Get("client_assertion_type"), expectedAssertionType; got != want {
			t.Errorf("client_assertion_type = %q; want %q", got, want)
		}

		assertion = r.Form.Get("client_assertion")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	for _, conf := range []*Config{
		{
			ClientID:       "CLIENT_ID",
			Scopes:         strings.Split(scopes, " "),
			TokenURL:       ts.URL + "/token",
			EndpointParams: url.Values{"audience": {audience}},
			AuthStyle:      oauth2.AuthStylePrivateKeyJWT,
			PrivateKey:     dummyPrivateKey,
			KeyID:          "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			ClientID:       "CLIENT_ID_set_jwt_expiration_time",
			Scopes:         strings.Split(scopes, " "),
			TokenURL:       ts.URL + "/token",
			EndpointParams: url.Values{"audience": {audience}},
			AuthStyle:      oauth2.AuthStylePrivateKeyJWT,
			PrivateKey:     dummyPrivateKey,
			KeyID:          "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			JWTExpires:     time.Minute,
		},
	} {
		t.Run(conf.ClientID, func(t *testing.T) {
			_, err := conf.TokenSource(context.Background()).Token()
			if err != nil {
				t.Fatalf("Failed to fetch token: %v", err)
			}
			parts := strings.Split(assertion, ".")
			if len(parts) != 3 {
				t.Fatalf("assertion = %q; want 3 parts", assertion)
			}
			gotJson, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("invalid token payload; err = %v", err)
			}
			claimSet := jws.ClaimSet{}
			if err := json.Unmarshal(gotJson, &claimSet); err != nil {
				t.Errorf("failed to unmarshal json token payload = %q; err = %v", gotJson, err)
			}
			if got, want := claimSet.Iss, conf.ClientID; got != want {
				t.Errorf("payload iss = %q; want %q", got, want)
			}
			if claimSet.Jti == "" {
				t.Errorf("payload jti is empty")
			}
			expectedDuration := time.Hour
			if conf.JWTExpires > 0 {
				expectedDuration = conf.JWTExpires
			}
			if got, want := claimSet.Exp, time.Now().Add(expectedDuration).Unix(); got != want {
				t.Errorf("payload exp = %q; want %q", got, want)
			}
			if got, want := claimSet.Aud, conf.TokenURL; got != want {
				t.Errorf("payload aud = %q; want %q", got, want)
			}
			if got, want := claimSet.Sub, conf.ClientID; got != want {
				t.Errorf("payload sub = %q; want %q", got, want)
			}
		})
	}
}

func TestTokenRefreshRequest(t *testing.T) {
	internal.ResetAuthCache()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL: %q", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type = %q; want %q", got, want)
		}
		body, _ := ioutil.ReadAll(r.Body)
		const want = "audience=audience1&grant_type=client_credentials&scope=scope1+scope2"
		if string(body) != want {
			t.Errorf("Unexpected refresh token payload.\n got: %s\nwant: %s\n", body, want)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "foo", "refresh_token": "bar"}`)
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	c := conf.Client(context.Background())
	c.Get(ts.URL + "/somethingelse")
}
