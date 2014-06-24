package google

import (
	"log"
	"net/http"

	"github.com/golang/oauth2"
	"google.golang.org/appengine"
)

func Example_webServer() {
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	config, err := NewConfig(&oauth2.Options{
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
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	config, err := NewServiceAccountConfig(&oauth2.JWTOptions{
		Email: "xxx@developer.gserviceaccount.com",
		// The path to the pem file. If you have a p12 file instead, you
		// can use `openssl` to export the private key into a pem file.
		// $ openssl pkcs12 -in key.p12 -out key.pem -nodes
		PemFilename: "/path/to/pem/file.pem",
		Scopes: []string{
			"https://www.googleapis.com/auth/bigquery",
		},
	})
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

	// Alternatively you can iniate a transport with
	// a token read from the cache.
	// If the existing access token expires, and a new access token is
	// retrieved, the newly fetched token will be written to the cache.
	cache := NewFileCache("/path/to/file")
	t, err := conf.NewTransportWithCache(cache)
	if err != nil {
		log.Fatal(err)
	}
	client = http.Client{Transport: t}
	// The following request will be authorized by the token
	// retrieved from the cache.
	client.Get("...")
}

func Example_appEngine() {
	context := appengine.NewContext(nil)
	config, err := NewAppEngineConfig(context, []string{
		"https://www.googleapis.com/auth/bigquery",
	})
	if err != nil {
		log.Fatal(err)
	}

	// The following client will be authorized by the App Engine
	// app's service account for the provided scopes.
	client := http.Client{Transport: config.NewTransport()}
	client.Get("...")
}

func Example_computeEngine() {
	// If no other account is specified, "default" is in use.
	config, err := NewComputeEngineConfig("")
	if err != nil {
		log.Fatal(err)
	}
	client := http.Client{Transport: config.NewTransport()}
	client.Get("...")
}
