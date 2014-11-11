package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type mockTokenFetcher struct{ token *Token }

func (f *mockTokenFetcher) Fn() func(*Token) (*Token, error) {
	return func(*Token) (*Token, error) {
		return f.token, nil
	}
}

func (f *mockTokenFetcher) FetchToken(existing *Token) (*Token, error) {
	return f.token, nil
}

func TestInitialTokenRead(t *testing.T) {
	tr := newTransport(http.DefaultTransport, nil, &Token{AccessToken: "abc"})
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer abc" {
			t.Errorf("Transport doesn't set the Authorization header from the initial token")
		}
	})
	defer server.Close()
	client := http.Client{Transport: tr}
	client.Get(server.URL)
}

func TestTokenFetch(t *testing.T) {
	fetcher := &mockTokenFetcher{
		token: &Token{
			AccessToken: "abc",
		},
	}
	tr := newTransport(http.DefaultTransport, fetcher.Fn(), nil)
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer abc" {
			t.Errorf("Transport doesn't set the Authorization header from the fetched token")
		}
	})
	defer server.Close()

	client := http.Client{Transport: tr}
	client.Get(server.URL)
	if tr.Token().AccessToken != "abc" {
		t.Errorf("New token is not set, found %v", tr.Token())
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

func TestExtraIntWithInt(t *testing.T) {
	token := &Token{
		raw: map[string]interface{}{
			"expires": int(1234567),
		},
	}

	val := token.ExtraInt("expires")
	if val != int(1234567) {
		t.Errorf("ExtraInt should return int value 1234567, got %T %d instead", val, val)
	}
}

func TestExtraIntWithFloat64(t *testing.T) {
	token := &Token{
		raw: map[string]interface{}{
			"expires": float64(1234567),
		},
	}

	val := token.ExtraInt("expires")
	if val != int(1234567) {
		t.Errorf("ExtraInt should return int value 1234567, got %T %d instead", val, val)
	}
}

func TestExtraIntWithURLValues(t *testing.T) {
	token := &Token{
		raw: url.Values{
			"expires": []string{"1234567"},
		},
	}

	val := token.ExtraInt("expires")
	if val != int(1234567) {
		t.Errorf("ExtraInt should return int value 1234567, got %T %d instead", val, val)
	}
}

func TestExtraIntWithString(t *testing.T) {
	token := &Token{
		raw: map[string]interface{}{
			"expires": "1234567",
		},
	}

	val := token.ExtraInt("expires")
	if val != int(0) {
		t.Errorf("ExtraInt should return int value 0, got %T %d instead", val, val)
	}
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
