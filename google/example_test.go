package google

import (
	"log"
	"net/http"

	"github.com/golang/oauth2"
)

func Example_webServer() {
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	config, err := NewConfig(&oauth2.Opts{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURL:  "YOUR_REDIRECT_URL",
		Scopes: []string{
			"https://www.googleapis.com/auth/bigquery",
			"https://www.googleapis.com/auth/blogger"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Redirect user to Google's consent page to ask for permission
	// for the scopes specified above.
	url, err := config.AuthCodeURL("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Handle the exchange code to initiate a transport
	t, err := config.NewTransportWithCode("exchange-code")
	if err != nil {
		log.Fatal(err)
	}
	client := http.Client{Transport: t}
	client.Get("...")

	// Alternatively you can initiate a new transport
	// with a token from a cache.
	cache := oauth2.NewFileCache("/path/to/file")
	// NewTransportWithCache will try to read the cached
	// token, if any error occurs, it returns the error.
	// If a token is available at the cache, initiates
	// a new transport authorized and authenticated with
	// the read token. If token expires, and a new access
	// token is retrieved, it writes the newly fetched
	// token to the cache.
	t, err = config.NewTransportWithCache(cache)
	if err != nil {
		log.Fatal(err)
	}
	client = http.Client{Transport: t}
	client.Get("...")
}

func Example_serviceAccounts() {

}

func Example_appEngine() {

}

func Example_computeEngine() {

}
