package oauth2

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestTransportWithNilHeader tests that the Transport.RoundTrip method
// correctly handles requests with nil Headers.
func TestTransportWithNilHeader(t *testing.T) {
	// Create a mock token source that returns a fixed token
	tokenSource := StaticTokenSource(&Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
	})

	// Create a mock http server to verify the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the Authorization header was correctly set
		authHeader := r.Header.Get("Authorization")
		expectedHeader := "Bearer test-access-token"
		if authHeader != expectedHeader {
			t.Errorf("expected authorization header %q, got %q", expectedHeader, authHeader)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create Transport with our token source
	transport := &Transport{
		Source: tokenSource,
		Base:   http.DefaultTransport,
	}

	// Create a request with nil Header
	reqURL, _ := url.Parse(server.URL)
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		// Header is intentionally nil
	}

	// Make the request using our Transport
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundTrip failed with nil Header: %v", err)
	}
	defer resp.Body.Close()

	// Verify response status
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
