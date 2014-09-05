package oauth2_test

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/golang/oauth2"
)

// TODO(jbd): Remove after Go 1.4.
// Related to https://codereview.appspot.com/107320046
func TestA(t *testing.T) {}

func Example_config() {
	conf, err := oauth2.NewConfig(&oauth2.Options{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURL:  "YOUR_REDIRECT_URL",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
	},
		"https://provider.com/o/oauth2/auth",
		"https://provider.com/o/oauth2/token")
	if err != nil {
		log.Fatal(err)
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", "online", "auto")
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect URL.
	// NewTransportWithCode will do the handshake to retrieve
	// an access token and initiate a Transport that is
	// authorized and authenticated by the retrieved token.
	var authorizationCode string
	if _, err = fmt.Scan(&authorizationCode); err != nil {
		log.Fatal(err)
	}
	t, err := conf.NewTransportWithCode(authorizationCode)
	if err != nil {
		log.Fatal(err)
	}

	// You can use t to initiate a new http.Client and
	// start making authenticated requests.
	client := http.Client{Transport: t}
	client.Get("...")
}

func Example_jWTConfig() {
	conf, err := oauth2.NewJWTConfig(&oauth2.JWTOptions{
		Email: "xxx@developer.gserviceaccount.com",
		// The contents of your RSA private key or your PEM file
		// that contains a private key.
		// If you have a p12 file instead, you
		// can use `openssl` to export the private key into a pem file.
		//
		//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
		//
		// It only supports PEM containers with no passphrase.
		PrivateKey: []byte("PRIVATE KEY CONTENTS"),
		Scopes:     []string{"SCOPE1", "SCOPE2"},
	},
		"https://provider.com/o/oauth2/token")
	if err != nil {
		log.Fatal(err)
	}

	// Initiate an http.Client, the following GET request will be
	// authorized and authenticated on the behalf of
	// xxx@developer.gserviceaccount.com.
	client := http.Client{Transport: conf.NewTransport()}
	client.Get("...")

	// If you would like to impersonate a user, you can
	// create a transport with a subject. The following GET
	// request will be made on the behalf of user@example.com.
	client = http.Client{Transport: conf.NewTransportWithUser("user@example.com")}
	client.Get("...")
}
