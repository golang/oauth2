package oauth2

import (
	"fmt"
	"log"
	"net/http"
)

func Example_config() {
	conf, err := NewConfig(&Options{
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
	url, err := conf.AuthCodeURL("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the exchange code that is handled by the redirect URL.
	// NewTransportWithCode will do the handshake to retrieve
	// an access token and iniate a Transport that is
	// authorized and authenticated the retrieved token.
	var exchangeCode string
	if _, err = fmt.Scan(&exchangeCode); err != nil {
		log.Fatal(err)
	}
	t, err := conf.NewTransportWithCode(exchangeCode)
	if err != nil {
		log.Fatal(err)
	}

	// You can use t to initiate a new http.Client and
	// start making authenticated requests.
	client := http.Client{Transport: t}
	client.Get("...")

	// Alternatively, you can initiate a new transport
	// with tokens from a cache.
	cache := NewFileCache("/path/to/file")
	// NewTransportWithCache will try to read the cached
	// token, if any error occurs, it returns the error.
	// If a token is available at the cache, initiates
	// a new transport authorized and authenticated with
	// the read token. If token expires, and a new access
	// token is retrieved, it writes the newly fetched
	// token to the cache.
	t, err = conf.NewTransportWithCache(cache)
	if err != nil {
		log.Fatal(err)
	}
	client = http.Client{Transport: t}
	client.Get("...")
}

func Example_jWTConfig() {
	conf, err := NewJWTConfig(&JWTOptions{
		Email: "xxx@developer.gserviceaccount.com",
		// The path to the pem file. If you have a p12 file instead, you
		// can use `openssl` to export the private key into a pem file.
		// $ openssl pkcs12 -in key.p12 -out key.pem -nodes
		PemFilename: "/path/to/pem/file.pem",
		Scopes:      []string{"SCOPE1", "SCOPE2"},
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
