package externalaccountauthorizeduser

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/internal/sts_exchange"
)

const expiryDelta = 10 * time.Second

var (
	expiry    = time.Unix(234852, 0)
	testNow   = func() time.Time { return expiry }
	testValid = func(t oauth2.Token) bool {
		return t.AccessToken != "" && !t.Expiry.Round(0).Add(-expiryDelta).Before(testNow())
	}
	//return true}
)

type testRefreshTokenServer struct {
	URL           string
	Authorization string
	ContentType   string
	Body          string
	ResponseJSON  *sts_exchange.Response
	Response      string
	server        *httptest.Server
}

func (trts *testRefreshTokenServer) Run(t *testing.T) (string, error) {
	if trts.server != nil {
		return "", errors.New("Server is already running")
	}
	trts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), trts.URL; got != want {
			t.Errorf("URL.String(): got %v but want %v", got, want)
		}
		headerAuth := r.Header.Get("Authorization")
		if got, want := headerAuth, trts.Authorization; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, trts.ContentType; got != want {
			t.Errorf("got %v but want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed reading request body: %s.", err)
		}
		if got, want := string(body), trts.Body; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		if trts.ResponseJSON != nil {
			content, err := json.Marshal(trts.ResponseJSON)
			if err != nil {
				t.Fatalf("unable to marshall response JSON")
			}
			w.Write(content)
		} else {
			w.Write([]byte(trts.Response))
		}
	}))
	return trts.server.URL, nil
}

func (trts *testRefreshTokenServer) Close() error {
	if trts.server == nil {
		return errors.New("No server is running")
	}
	trts.server.Close()
	trts.server = nil
	return nil
}

// Tests

func TestExernalAccountAuthorizedUser_JustToken(t *testing.T) {
	config := &Config{
		Token:  "AAAAAAA",
		Expiry: now().Add(time.Hour), // Is there a way to stub the timeNow in token.go from here?
	}
	ts, err := config.TokenSource(context.Background())
	if err != nil {
		t.Fatalf("Error getting token source: %v", err)
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Error retrieving Token: %v", err)
	}
	if got, want := token.AccessToken, "AAAAAAA"; got != want {
		t.Fatalf("Unexpected access token, got %v, want %v", got, want)
	}
}

func TestExernalAccountAuthorizedUser_JustRefresh(t *testing.T) {
	server := &testRefreshTokenServer{
		URL:           "/",
		Authorization: "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=",
		ContentType:   "application/x-www-form-urlencoded",
		Body:          "grant_type=refresh_token&refresh_token=BBBBBBBBB",
		ResponseJSON: &sts_exchange.Response{
			ExpiresIn:   3600,
			AccessToken: "AAAAAAA",
		},
	}

	url, err := server.Run(t)
	if err != nil {
		t.Fatalf("Error starting server")
	}
	defer server.Close()

	config := &Config{
		RefreshToken: "BBBBBBBBB",
		TokenURL:     url,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	}
	ts, err := config.TokenSource(context.Background())
	if err != nil {
		t.Fatalf("Error getting token source: %v", err)
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Error retrieving Token: %v", err)
	}
	if got, want := token.AccessToken, "AAAAAAA"; got != want {
		t.Fatalf("Unexpected access token, got %v, want %v", got, want)
	}
}

func TestExternalAccountAuthorizedUser_Blank(t *testing.T) {
	config := &Config{}
	ts, err := config.TokenSource(context.Background())
	if err == nil {
		t.Fatalf("Expected error, but received none")
	}
	if got, want := err.Error(), "oauth2/google: The credentials do not contain the necessary fields need to refresh the access token. You must specify refresh_token, token_url, client_id, and client_secret."; got != want {
		t.Fatalf("Unexpected error, got %v, want %v", got, want)
	}
}
