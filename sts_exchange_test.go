package oauth2_test

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"testing"

	"golang.org/x/oauth2/google/externalaccount"
)

var _ externalaccount.SubjectTokenSupplier = fakeSupplier{}

type fakeSupplier struct{}

func (f fakeSupplier) SubjectToken(_ context.Context, _ externalaccount.SupplierOptions) (string, error) {
	return "test-token", nil
}

var _ http.RoundTripper = fakeRT{}

type fakeRT struct {
	body string
}

func (f fakeRT) RoundTrip(_ *http.Request) (*http.Response, error) {
	status := http.StatusUnauthorized
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(f.body))),
	}, nil
}

func TestSTSExchange_error_handling(t *testing.T) {
	t.Parallel()

	// Arrange
	body := `{"reason": "client does not exist"}`
	client := &http.Client{Transport: fakeRT{body: body}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	source, err := externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience:             "aud",
		SubjectTokenType:     "test-token",
		TokenURL:             "url",
		Scopes:               []string{},
		SubjectTokenSupplier: fakeSupplier{},
	})
	if err != nil {
		t.Errorf("got unexpected error while token source building: %s", err)
	}

	// Act
	_, err = source.Token()

	// Assert
	if err == nil {
		t.Errorf("expected token issuance error")
	}
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		t.Errorf("expected an instance of RetrieveError, got error: %s", err)
	}

	if string(retrieveErr.Body) != body {
		t.Errorf("expected body content `%s`, got: `%s`", body, retrieveErr.Body)
	}

	if retrieveErr.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected unathorized status code, got: %s", retrieveErr.ErrorCode)
	}
}
