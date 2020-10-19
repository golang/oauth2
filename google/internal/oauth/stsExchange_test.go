package externalaccount

import (
"github.com/google/go-cmp/cmp"
"golang.org/x/oauth2"
"net/http"
"net/http/httptest"
"testing"
)

var auth = ClientAuthentication{
	AuthStyle: oauth2.AuthStyleInHeader,
	ClientID: clientID,
	ClientSecret: clientSecret,
}

var tokenRequest = STSTokenExchangeRequest{
	ActingParty: struct {
		ActorToken     string
		ActorTokenType string
	}{},
	GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
	Resource:           "",
	Audience:           "32555940559.apps.googleusercontent.com",  //TODO: Make sure audience is correct in this test (might be mismatched)
	Scope:              []string{"https://www.googleapis.com/auth/devstorage.full_control"},
	RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	SubjectToken:       "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJjNmZhNmY1OTUwYTdjZTQ2NWZjZjI0N2FhMGIwOTQ4MjhhYzk1MmMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzMzE4NTQxMDA5MDU3Mzc4MzI4IiwiaGQiOiJnb29nbGUuY29tIiwiZW1haWwiOiJpdGh1cmllbEBnb29nbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJyWUtBTjZwX21rS0U4U2ItN3ZGalBBIiwiaWF0IjoxNjAxNTk0NDY1LCJleHAiOjE2MDE1OTgwNjV9.mWOLjD6ghfgrFNcm_1h-wrpLlKFc2WSS13lu2L5t4549uYhX5DEbI7MmeUEwXSffrns1ljcdbJm4nXymXK3AH6ftRV17O3BnOsWngxKj5eKhzOMF308YNXjBKTDiu_crzjCpf_2ng03IIGbFsTvAUx4wvWhnFO-z4xl2tb13OMCxpkw52dO1ZcFhw0d_1iUj_q0UL9E15ADL4SOr-BVtXerWPhNVBplTw8gzL4HHmo2GGUA_ilQpJzD528BKLygemqy1taXZwOGJEAUYkcKm8DhA0NJWneUyqHN6qbs0wm_d_nZsiFx9CIDblt1dUkgfuPIsno-xrkkkwubcv1WlgA",
	SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
}

var serverReq = http.Request{
	Method:           "POSTURL:/",
	URL:              nil,
	Proto:            "HTTP/1.1",
	ProtoMajor:       1,
	ProtoMinor:       1,
	Header:           map[string][]string{
		"Accept-Encoding": []string{"gzip"},
		"Authorization": []string{"Basic cmJyZ25vZ25yaG9uZ28zYmk0Z2I5Z2hnOWc6bm90c29zZWNyZXQ="},
		"Content-Length": []string{"1192"},
		"Content-Type": []string{"application/x-www-form-urlencoded"},
		"User-Agent": []string{"Go-http-client/1.1"},
	},
	Body:             nil, //TODO: Construct this struct
	ContentLength:    1192,
	Close:            false,
	Host:             "127.0.0.1:41147", //TODO: Does this conflict due to separate addresses?
	Form:             nil,  //TODO: Should Form, PostForm, TransferEncoding, etc be initialized with Make?
	PostForm:         nil,
	MultipartForm:    nil,
	Trailer:          nil,
	RemoteAddr:       "127.0.0.1:52760",
	RequestURI:       "/",
	TLS:              nil,
	Cancel:           nil,
	Response:         nil,
}

var serverResp = http.Response{
	Status:           "200 OK",
	StatusCode:       200,
	Proto:            "HTTP/1.1",
	ProtoMajor:       1,
	ProtoMinor:       1,
	Header:           map[string][]string{
		"Connection":[]string{"keep-alive"},
		"Content-Length":[]string{"362"},
		"Content-Type":[]string{"application/json; charset=utf-8"},
		"Date":[]string{"Wed, 07 Oct 2020 21:54:27 GMT"},
		"X-Powered-By":[]string{"Express"},
	},
	Body:             nil,
	ContentLength:    0,
	TransferEncoding: nil,
	Close:            false,
	Uncompressed:     false,
	Trailer:          nil,
	Request:          nil,
	TLS:              nil,
}

func TestExchangeToken(t *testing.T) {



	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if diff := cmp.Diff(*r, serverReq); diff != "" {
			t.Errorf("mismatched messages received by mock server (-want +got): \n%s", diff)
		}
		if r.URL.String() !=

		return
	}))

	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	//TODO: Call TokenExchange, make sure I get the right results
	resp, err := ExchangeToken(ts.URL, &tokenRequest, auth, headers, nil)
	if err != nil {
		t.Errorf("ExchangeToken failed with error: %s", err)
	}
}