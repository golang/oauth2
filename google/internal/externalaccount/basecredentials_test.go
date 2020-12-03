package externalaccount

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var testBaseCredSource = CredentialSource{
	File: "internalTestingFile",
}

var testConfig = Config{
	Audience:         "32555940559.apps.googleusercontent.com",
	SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	//TokenURL: "http://localhost:8080/v1/token",
	TokenInfoURL:                   "http://localhost:8080/v1/tokeninfo",
	ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-gcs-admin@$PROJECT_ID.iam.gserviceaccount.com:generateAccessToken",
	ClientSecret:                   "notsosecret",
	ClientID:                       "rbrgnognrhongo3bi4gb9ghg9g",
	CredentialSource:               testBaseCredSource,
	Scopes:                         []string{"https://www.googleapis.com/auth/devstorage.full_control"},
}

var baseCredsRequestBody = "audience=32555940559.apps.googleusercontent.com&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&options=null&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.full_control&subject_token=Sample.Subject.Token&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
var baseCredsResponseBody = `{"access_token":"Sample.Access.Token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/cloud-platform"}`

var correctAT = "Sample.Access.Token"

func TestToken_Func(t *testing.T) {

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*I'm not sure whether this testing is necessary or not.  There's an argument that it should be here for completeness,
		but it's also just mimicking similar testing done in sts_exchange_test.go
		*/
		if got, want := r.URL.String(), "/"; got != want {
			t.Errorf("Unexpected request URL: got %v but want %v", got, want)
		}
		headerAuth := r.Header.Get("Authorization")
		if got, want := headerAuth, "Basic cmJyZ25vZ25yaG9uZ28zYmk0Z2I5Z2hnOWc6bm90c29zZWNyZXQ="; got != want {
			t.Errorf("Unexpected autohrization header: got %v but want %v", got, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if got, want := headerContentType, "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Unexpected Content-Type header: got %v but want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if got, want := string(body), baseCredsRequestBody; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(baseCredsResponseBody))
	}))

	testConfig.TokenURL = targetServer.URL
	ourTS := tokenSource{
		ctx:  context.Background(),
		conf: &testConfig,
	}

	tok, err := ourTS.Token()
	if err != nil {
		t.Errorf("Unexpected error: %e", err)
	}
	if tok.AccessToken != correctAT {
		t.Errorf("Unexpected access token: got %v, but wanted %v", tok.AccessToken, correctAT)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("Unexpected TokenType: got %v, but wanted \"Bearer\"", tok.TokenType)
	}
	//We don't check the correct expiry here because that's dependent on the current time.

}
