package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockCache struct{ token *Token }

func (m *mockCache) Read() (token *Token, err error) {
	return m.token, nil
}

func (m *mockCache) Write(token *Token) {
	m.token = token
}

type mockTokenFetcher struct{ token *Token }

func (f *mockTokenFetcher) FetchToken(existing *Token) (*Token, error) {
	return f.token, nil
}

func TestInitialTokenRead(t *testing.T) {
	cache := &mockCache{token: &Token{
		AccessToken: "abc",
	}}
	tr, _ := NewAuthorizedTransportWithCache(nil, cache)
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer abc" {
			t.Errorf("Transport doesn't read the token initially from the cache")
		}
	})
	defer server.Close()
	client := http.Client{Transport: tr}
	client.Get(server.URL)
}

func TestTokenWrite(t *testing.T) {
	fetcher := &mockTokenFetcher{
		token: &Token{
			AccessToken: "abc",
		},
	}
	// cache with expired token
	cache := &mockCache{token: &Token{}}
	tr, _ := NewAuthorizedTransportWithCache(fetcher, cache)
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer abc" {
			t.Errorf("Transport doesn't read the token initially from the cache")
		}
	})
	defer server.Close()

	client := http.Client{Transport: tr}
	client.Get(server.URL)
	if cache.token.AccessToken != "abc" {
		t.Errorf("New token is not cached, found %v", cache.token)
	}
}

func TestExpiredWithNoAccessToken(t *testing.T) {
	token := &Token{}
	if !token.Expired() {
		t.Errorf("Token should be expired if no access token is provided")
	}
}

func TestExpiredWithExpiry(t *testing.T) {
	token := &Token{
		Expiry: time.Now().Add(-5 * time.Hour),
	}
	if !token.Expired() {
		t.Errorf("Token should be expired if no access token is provided")
	}
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
