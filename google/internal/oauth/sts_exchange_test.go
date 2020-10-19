package externalaccount

import (
	"github.com/google/go-cmp"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var auth = ClientAuthentication{
	AuthStyle:    oauth2.AuthStyleInHeader,
	ClientID:     clientID,
	ClientSecret: clientSecret,
}

var tokenRequest = STSTokenExchangeRequest{
	ActingParty: struct {
		ActorToken     string
		ActorTokenType string
	}{},
	GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
	Resource:           "",
	Audience:           "32555940559.apps.googleusercontent.com", //TODO: Make sure audience is correct in this test (might be mismatched)
	Scope:              []string{"https://www.googleapis.com/auth/devstorage.full_control"},
	RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	SubjectToken:       "eyJhbGciOiJSUzI1NiIsImtpIjJjNmZhNmY1OTUwYTdjZTQ2NWZjZjI0N2FhMGIwOTQ4MjhhYzk1MmMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzMzE4NTQxMDA5MDU3Mzc4MzI4IiwiaGQiOiJnb29nbGUuY29tIiwiZW1haWwiOiJpdGh1cmllbEBnb29nbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJyWUtBTjZwX21rS0U4U2ItN3ZGalBBIiwiaWF0IjoxNjAxNTk0NDY1LCJleHAiOjE2MDE1OTgwNjV9.mWOLjD6ghfgrFNcm_1h-wrpLlKFc2WSS13lu2L5t4549uYhX5DEbI7MmeUEwXSffrns1ljcdbJm4nXymXK3AH6ftRV17O3BnOsWngxKj5eKhzOMF308YNXjBKTDiu_crzjCpf_2ng03IIGbFsTvAUx4wvWhnFO-z4xl2tb13OMCxpkw52dO1ZcFhw0d_1iUj_q0UL9E15ADL4SOr-BVtXerWPhNVBplTw8gzL4HHmo2GGUA_ilQpJzD528BKLygemqy1taXZwOGJEAUYkcKm8DhA0NJWneUyqHN6qbs0wm_d_nZsiFx9CIDblt1dUkgfuPIsno-xrkkkwubcv1WlgA",
	SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
}

var requestbody = "audience=32555940559.apps.googleusercontent.com&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.full_control&subject_token=eyJhbGciOiJSUzI1NiIsImtpIjJjNmZhNmY1OTUwYTdjZTQ2NWZjZjI0N2FhMGIwOTQ4MjhhYzk1MmMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzMzE4NTQxMDA5MDU3Mzc4MzI4IiwiaGQiOiJnb29nbGUuY29tIiwiZW1haWwiOiJpdGh1cmllbEBnb29nbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJyWUtBTjZwX21rS0U4U2ItN3ZGalBBIiwiaWF0IjoxNjAxNTk0NDY1LCJleHAiOjE2MDE1OTgwNjV9.mWOLjD6ghfgrFNcm_1h-wrpLlKFc2WSS13lu2L5t4549uYhX5DEbI7MmeUEwXSffrns1ljcdbJm4nXymXK3AH6ftRV17O3BnOsWngxKj5eKhzOMF308YNXjBKTDiu_crzjCpf_2ng03IIGbFsTvAUx4wvWhnFO-z4xl2tb13OMCxpkw52dO1ZcFhw0d_1iUj_q0UL9E15ADL4SOr-BVtXerWPhNVBplTw8gzL4HHmo2GGUA_ilQpJzD528BKLygemqy1taXZwOGJEAUYkcKm8DhA0NJWneUyqHN6qbs0wm_d_nZsiFx9CIDblt1dUkgfuPIsno-xrkkkwubcv1WlgA&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
var responseBody = `{"access_token":"ya29.a0AfH6SMCqKiKaHEpqs9sl6cocVlqG2dvP2g7eURqGNCfUyKZ6lYSHz531aioS3_0w_xdNDfj6A-Hzk6-0-M6olf3O-zfcGFd678lVuvplpclaK4XQ4ete6_9xSUFU08RefwE53rf2OW8FOQvjpQB-PmPhHZTzK99YYHNtjas","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/cloud-platform"}`
var expectedToken = STSTokenExchangeResponse{
	AccessToken:     "ya29.a0AfH6SMCqKiKaHEpqs9sl6cocVlqG2dvP2g7eURqGNCfUyKZ6lYSHz531aioS3_0w_xdNDfj6A-Hzk6-0-M6olf3O-zfcGFd678lVuvplpclaK4XQ4ete6_9xSUFU08RefwE53rf2OW8FOQvjpQB-PmPhHZTzK99YYHNtjas",
	IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	TokenType:       "Bearer",
	ExpiresIn:       3600,
	Scope:           "https://www.googleapis.com/auth/cloud-platform",
	RefreshToken:    "",
}

func TestExchangeToken(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic cmJyZ25vZ25yaG9uZ28zYmk0Z2I5Z2hnOWc6bm90c29zZWNyZXQ=" {
			t.Errorf("Unexpected autohrization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded]" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != requestbody {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(responseBody))
	}))

	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	resp, err := ExchangeToken(ts.URL, &tokenRequest, auth, headers, nil)
	if err != nil {
		t.Errorf("ExchangeToken failed with error: %s", err)
	}

	if diff := cmp.Diff(resp, expectedToken); diff != "" {
		t.Errorf("mismatched messages received by mock server (-want +got): \n%v", diff)
	}

}
