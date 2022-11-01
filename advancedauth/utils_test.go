package advancedauth_test

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/cloudentity/oauth2"
)

func expectHeader(t *testing.T, r *http.Request, header string, expected string) {
	actual := r.Header.Get(header)
	if actual != expected {
		t.Fatalf("Expected header %s to be %s, got %s", header, expected, actual)
	}
}

func expectURL(t *testing.T, r *http.Request, expected string) {
	actual := r.URL.String()
	if actual != expected {
		t.Fatalf("Expected url to be %s, got %s", expected, actual)
	}
}

func expectBody(t *testing.T, r *http.Request, expected string) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		r.Body.Close()
	}
	if err != nil {
		t.Fatalf("failed reading request body: %s.", err)
	}
	actual := string(body)
	if actual != expected {
		t.Fatalf("Expected body to be %s, got %s", expected, actual)
	}
}

func expectAccessToken(t *testing.T, expected *oauth2.Token, actual *oauth2.Token) {
	if !actual.Valid() {
		t.Fatalf("token invalid. got: %+v", actual)
	}
	if actual.AccessToken != expected.AccessToken {
		t.Fatalf("Access token = %q; want %q", actual.AccessToken, expected.AccessToken)
	}
	if actual.TokenType != expected.TokenType {
		t.Fatalf("token type = %q; want %q", actual.TokenType, expected.TokenType)
	}
}

func expectFormParam(t *testing.T, r *http.Request, param string, expected string) {
	actual := r.FormValue(param)
	if actual != expected {
		t.Fatalf("Expected form param %s to be %s, got %s", param, expected, actual)
	}
}

func expectStringsEqual(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Fatalf("Expected %s and %s to be equal", expected, actual)
	}
}

func expectStringNonEmpty(t *testing.T, actual string) {
	if actual == "" {
		t.Fatalf("Expected not empty %s", actual)
	}
}

func expectTrue(t *testing.T, actual bool) {
	if !actual {
		t.Fatalf("Expected true %t", actual)
	}
}
