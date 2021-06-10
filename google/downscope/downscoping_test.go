package downscope

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	standardReqBody  = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&options=%257B%2522accessBoundary%2522%253A%257B%2522accessBoundaryRules%2522%253A%255B%257B%2522availableResource%2522%253A%2522test1%2522%252C%2522availablePermissions%2522%253A%255B%2522Perm1%252C%2Bperm2%2522%255D%257D%255D%257D%257D&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=Mellon&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
	standardRespBody = `{"access_token":"Open Sesame","expires_in":432,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`
)

func Test_NewAccessBoundary(t *testing.T) {
	got := AccessBoundary{make([]AccessBoundaryRule, 0)}
	want := AccessBoundary{nil}
	if got.AccessBoundaryRules == nil || len(got.AccessBoundaryRules) != 0 {
		t.Errorf("NewAccessBoundary() = %v; want %v", got, want)
	}
}

func Test_DownscopedTokenSource(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Unexpected request method, %v is found", r.Method)
		}
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found", r.URL)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		if got, want := string(body), standardReqBody; got != want {
			t.Errorf("Unexpected exchange payload: got %v but want %v,", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(standardRespBody))

	}))
	new := AccessBoundary{make([]AccessBoundaryRule, 0)}
	new.AccessBoundaryRules = append(new.AccessBoundaryRules, AccessBoundaryRule{"test1", []string{"Perm1, perm2"}, nil})
	myTok := oauth2.Token{AccessToken: "Mellon"}
	tmpSrc := oauth2.StaticTokenSource(&myTok)
	out, err := downscopedTokenWithEndpoint(context.Background(), DownscopingConfig{tmpSrc, new}, ts.URL)
	if err != nil {
		t.Fatalf("NewDownscopedTokenSource failed with error: %v", err)
	}
	_, err = out.Token()
	if err != nil {
		t.Fatalf("Token() call failed with error %v", err)
	}
}

func Example() {
	ctx := context.Background()
	availableResource := "//storage.googleapis.com/projects/_/buckets/foo"
	availablePermissions := []string{"inRole:roles/storage.objectViewer"}


	// Initializes an accessBoundary
	myBoundary := AccessBoundary{make([]AccessBoundaryRule, 0)}

	// Add a new rule to the AccessBoundary
	myBoundary.AccessBoundaryRules = append(myBoundary.AccessBoundaryRules, AccessBoundaryRule{availableResource, availablePermissions, nil})

	// Get the token source for Application Default Credentials (DefaultTokenSource is a shorthand
	// for is a shortcut for FindDefaultCredentials(ctx, scope).TokenSource.
	// This example assumes that you've defined the GOOGLE_APPLICATION_CREDENTIALS environment variable
	rootSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Fatalf("failed to generate root token source; %v", err)
		return
	}
	myTokenSource, err := NewTokenSource(context.Background(), DownscopingConfig{rootSource, myBoundary})
	//myTokenSource, err := NewSource(rootSource, myBoundary)
	if err != nil {
		log.Fatalf("failed to generate downscoped token source: %v", err)
		return
	}
	fmt.Printf("%+v\n", myTokenSource)
	// You can now use the token held in myTokenSource to make
	// Google Cloud Storage calls.  A short example follows.

	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(myTokenSource))
	// bkt := storageClient.Bucket(bucketName)
	// obj := bkt.Object(objectName)
	// rc, err := obj.NewReader(ctx)
	// data, err := ioutil.ReadAll(rc)
	return
}