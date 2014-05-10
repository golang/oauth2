// Package google provides support for making
// OAuth2 authorized and authenticated HTTP requests
// to Google APIs. It supports the following
// authorization and authentications flows:
//   - Web Server
//   - Client-side
//   - Service Accounts
//   - Auth from Google Compute Engine
//   - Auth from Google App Engine
//
// For more information, please read
// https://developers.google.com/accounts/docs/OAuth2.
//
// Example usage:
//      // Web server flow usage:
//      // Specify your configuration.
//      // Your credentials should be obtained from the Google
//      // Developer Console (https://console.developers.google.com).
//      var config = google.NewConfig(&oauth2.Opts{
//              ClientID:     YOUR_CLIENT_ID,
//              ClientSecret: YOUR_CLIENT_SECRET,
//              RedirectURL:  "http://you.example.org/handler",
//              Scopes:       []string{ "scope1", "scope2" },
//      })
//
//      // A landing page redirects to Google to get the auth code.
//      func landing(w http.ResponseWriter, r *http.Request) {
//              http.Redirect(w, r, config.AuthCodeURL(""), http.StatusFound)
//      }
//
//      // The user will be redirected back to this handler, that takes the
//      // "code" query parameter and Exchanges it for an access token.
//      func handler(w http.ResponseWriter, r *http.Request) {
//              t, err := config.NewTransportWithCode(r.FormValue("code"))
//              // The Transport now has a valid Token. Create an *http.Client
//              // with which we can make authenticated API requests.
//              c := t.Client()
//              c.Post(...)
//      }
//
//      // Service accounts usage:
//      // Google Developer Console will provide a p12 file contains
//      // a private key. You need to export it to the pem format.
//      // Run the following command to generate a pem file that
//      // contains your private key:
//      // $ openssl pkcs12 -in /path/to/p12key.p12 -out key.pem -nodes
//      // Then, specify your configuration.
//      var config = google.NewServiceAccountConfig(&oauth2.JWTOpts{
//              Email:       "xxx@developer.gserviceaccount.com",
//              PemFilename: "/path/to/key.pem",
//              Scopes:      []string{
//                      "https://www.googleapis.com/auth/drive.readonly"
//              },
//      })
//
//      // Create a transport.
//      t, err := config.NewTransport()
//      // Or, you can create a transport that impersonates
//      // a Google user.
//      t, err := config.NewTransportWithUser(googleUserEmail)
//
//      // Create a client to make authorized requests.
//      c := t.Client()
//      c.Post(...)
//
package google

import (
	"github.com/rakyll/oauth2"
)

const (
	// Google endpoints.
	uriGoogleAuth  = "https://accounts.google.com/o/oauth2/auth"
	uriGoogleToken = "https://accounts.google.com/o/oauth2/token"
)

// ComputeEngineConfig represents a OAuth 2.0 consumer client
// running on Google Compute Engine.
type ComputeEngineConfig struct{}

// NewConfig creates a new OAuth2 config that uses Google
// endpoints.
func NewConfig(opts *oauth2.Options) (oauth2.Config, error) {
	return oauth2.NewConfig(opts, uriGoogleAuth, uriGoogleToken)
}

// NewServiceAccountConfig creates a new JWT config that can
// fetch Bearer JWT tokens from Google endpoints.
func NewServiceAccountConfig(opts *oauth2.JWTOptions) (oauth2.JWTConfig, error) {
	return oauth2.NewJWTConfig(opts, uriGoogleToken)
}

// NewComputeEngineConfig creates a new config that can fetch tokens
// from Google Compute Engine instance's metaserver.
func NewComputeEngineConfig() (*ComputeEngineConfig, error) {
	// Should fetch an access token from the meta server.
	return &ComputeEngineConfig{}, nil
}

// NewTransport creates an authorized transport.
func (c *ComputeEngineConfig) NewTransport() (oauth2.Transport, error) {
	return oauth2.NewAuthorizedTransport(c, nil), nil
}

// FetchToken retrieves a new access token via metadata server.
func (c *ComputeEngineConfig) FetchToken(existing *oauth2.Token) (*oauth2.Token, error) {
	panic("not yet implemented")
}
