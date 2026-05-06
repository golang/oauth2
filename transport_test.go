package oauth2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransportNilTokenSource(t *testing.T) {
	tr := &Transport{}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	resp, err := client.Get(server.URL)
	if err == nil {
		t.Errorf("got no errors, want an error with nil token source")
	}
	if resp != nil {
		t.Errorf("Response = %v; want nil", resp)
	}
}

type readCloseCounter struct {
	CloseCount int
	ReadErr    error
}

func (r *readCloseCounter) Read(b []byte) (int, error) {
	return 0, r.ReadErr
}

func (r *readCloseCounter) Close() error {
	r.CloseCount++
	return nil
}

func TestTransportCloseRequestBody(t *testing.T) {
	tr := &Transport{}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	body := &readCloseCounter{
		ReadErr: errors.New("readCloseCounter.Read not implemented"),
	}
	resp, err := client.Post(server.URL, "application/json", body)
	if err == nil {
		t.Errorf("got no errors, want an error with nil token source")
	}
	if resp != nil {
		t.Errorf("Response = %v; want nil", resp)
	}
	if expected := 1; body.CloseCount != expected {
		t.Errorf("Body was closed %d times, expected %d", body.CloseCount, expected)
	}
}

func TestTransportCloseRequestBodySuccess(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	body := &readCloseCounter{
		ReadErr: io.EOF,
	}
	resp, err := client.Post(server.URL, "application/json", body)
	if err != nil {
		t.Errorf("got error %v; expected none", err)
	}
	if resp == nil {
		t.Errorf("Response is nil; expected non-nil")
	}
	if expected := 1; body.CloseCount != expected {
		t.Errorf("Body was closed %d times, expected %d", body.CloseCount, expected)
	}
}

func TestTransportTokenSource(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer abc"; got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

// Test for case-sensitive token types, per https://github.com/golang/oauth2/issues/113
func TestTransportTokenSourceTypes(t *testing.T) {
	const val = "abc"
	tests := []struct {
		key  string
		val  string
		want string
	}{
		{key: "bearer", val: val, want: "Bearer abc"},
		{key: "mac", val: val, want: "MAC abc"},
		{key: "basic", val: val, want: "Basic abc"},
	}
	for _, tc := range tests {
		tr := &Transport{
			Source: StaticTokenSource(&Token{
				AccessToken: tc.val,
				TokenType:   tc.key,
			}),
		}
		server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
			if got, want := r.Header.Get("Authorization"), tc.want; got != want {
				t.Errorf("Authorization header (%q) = %q; want %q", val, got, want)
			}
		})
		defer server.Close()
		client := &http.Client{Transport: tr}
		res, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
}

func TestTokenValidNoAccessToken(t *testing.T) {
	token := &Token{}
	if token.Valid() {
		t.Errorf("got valid with no access token; want invalid")
	}
}

func TestExpiredWithExpiry(t *testing.T) {
	token := &Token{
		Expiry: time.Now().Add(-5 * time.Hour),
	}
	if token.Valid() {
		t.Errorf("got valid with expired token; want invalid")
	}
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

// TestNewClientCrossHostRedirectDoesNotLeakToken verifies that a client
// created with NewClient stops following redirects when the redirect target
// is on a different host, preventing the oauth2 transport from forwarding
// the bearer token to an unintended destination.
func TestNewClientCrossHostRedirectDoesNotLeakToken(t *testing.T) {
	tokenReceived := false
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			tokenReceived = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer victim.Close()

	// redirector lives on a different address (different host:port) from victim.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/stolen", http.StatusFound)
	}))
	defer redirector.Close()

	ts := StaticTokenSource(&Token{AccessToken: "SECRET_TOKEN"})
	client := NewClient(context.Background(), ts)

	resp, err := client.Get(redirector.URL + "/api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// The client must NOT have followed the cross-host redirect.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("got status %d; want %d (redirect should not be followed)", resp.StatusCode, http.StatusFound)
	}
	if tokenReceived {
		t.Error("token was forwarded to the redirect target; cross-host redirect should have been stopped")
	}
}

// TestNewClientSameHostRedirectIsFollowed verifies that same-host redirects
// are still followed (backward compatibility).
func TestNewClientSameHostRedirectIsFollowed(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/redirectme", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ts := StaticTokenSource(&Token{AccessToken: "MY_TOKEN"})
	client := NewClient(context.Background(), ts)

	resp, err := client.Get(server.URL + "/redirectme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if !called {
		t.Error("same-host redirect was not followed")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d; want 200", resp.StatusCode)
	}
}
