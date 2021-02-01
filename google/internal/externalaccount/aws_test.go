// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

var defaultTime = time.Date(2011, 9, 9, 23, 36, 0, 0, time.UTC)
var secondDefaultTime = time.Date(2020, 8, 11, 6, 55, 22, 0, time.UTC)

func setTime(testTime time.Time) func() time.Time {
	return func() time.Time {
		return testTime
	}
}

func setEnvironment(env map[string]string) func(string) string {
	return func(key string) string {
		value, _ := env[key]
		return value
	}
}

var defaultRequestSigner = &awsRequestSigner{
	RegionName: "us-east-1",
	AwsSecurityCredentials: awsSecurityCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	},
}

const (
	accessKeyID     = "ASIARD4OQDT6A77FR3CL"
	secretAccessKey = "Y8AfSaucF37G4PpvfguKZ3/l7Id4uocLXxX0+VTx"
	securityToken   = "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMiJGMEQCIH7MHX/Oy/OB8OlLQa9GrqU1B914+iMikqWQW7vPCKlgAiA/Lsv8Jcafn14owfxXn95FURZNKaaphj0ykpmS+Ki+CSq0AwhlEAAaDDA3NzA3MTM5MTk5NiIMx9sAeP1ovlMTMKLjKpEDwuJQg41/QUKx0laTZYjPlQvjwSqS3OB9P1KAXPWSLkliVMMqaHqelvMF/WO/glv3KwuTfQsavRNs3v5pcSEm4SPO3l7mCs7KrQUHwGP0neZhIKxEXy+Ls//1C/Bqt53NL+LSbaGv6RPHaX82laz2qElphg95aVLdYgIFY6JWV5fzyjgnhz0DQmy62/Vi8pNcM2/VnxeCQ8CC8dRDSt52ry2v+nc77vstuI9xV5k8mPtnaPoJDRANh0bjwY5Sdwkbp+mGRUJBAQRlNgHUJusefXQgVKBCiyJY4w3Csd8Bgj9IyDV+Azuy1jQqfFZWgP68LSz5bURyIjlWDQunO82stZ0BgplKKAa/KJHBPCp8Qi6i99uy7qh76FQAqgVTsnDuU6fGpHDcsDSGoCls2HgZjZFPeOj8mmRhFk1Xqvkbjuz8V1cJk54d3gIJvQt8gD2D6yJQZecnuGWd5K2e2HohvCc8Fc9kBl1300nUJPV+k4tr/A5R/0QfEKOZL1/k5lf1g9CREnrM8LVkGxCgdYMxLQow1uTL+QU67AHRRSp5PhhGX4Rek+01vdYSnJCMaPhSEgcLqDlQkhk6MPsyT91QMXcWmyO+cAZwUPwnRamFepuP4K8k2KVXs/LIJHLELwAZ0ekyaS7CptgOqS7uaSTFG3U+vzFZLEnGvWQ7y9IPNQZ+Dffgh4p3vF4J68y9049sI6Sr5d5wbKkcbm8hdCDHZcv4lnqohquPirLiFQ3q7B17V9krMPu3mz1cg4Ekgcrn/E09NTsxAqD8NcZ7C7ECom9r+X3zkDOxaajW6hu3Az8hGlyylDaMiFfRbBJpTIlxp7jfa7CxikNgNtEKLH9iCzvuSg2vhA=="
)

var requestSignerWithToken = &awsRequestSigner{
	RegionName: "us-east-2",
	AwsSecurityCredentials: awsSecurityCredentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SecurityToken:   securityToken,
	},
}

func setDefaultTime(req *http.Request) {
	// Don't use time.Format for this
	// Our output signature expects this to be a Monday, even though Sept 9, 2011 is a Friday
	req.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
}

func testRequestSigner(t *testing.T, rs *awsRequestSigner, input, expectedOutput *http.Request) {
	t.Helper()

	err := rs.SignRequest(input)
	if err != nil {
		t.Errorf("unexpected error: %q", err.Error())
	}

	if got, want := input.URL.String(), expectedOutput.URL.String(); !reflect.DeepEqual(got, want) {
		t.Errorf("url = %q, want %q", got, want)
	}
	if got, want := input.Method, expectedOutput.Method; !reflect.DeepEqual(got, want) {
		t.Errorf("method = %q, want %q", got, want)
	}
	for header := range expectedOutput.Header {
		if got, want := input.Header[header], expectedOutput.Header[header]; !reflect.DeepEqual(got, want) {
			t.Errorf("header[%q] = %q, want %q", header, got, want)
		}
	}
}

func TestAwsV4Signature_GetRequest(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithRelativePath(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/foo/bar/../..", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/foo/bar/../..", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithDotPath(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/./", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/./", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithPointlessDotPath(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/./foo", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/./foo", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=910e4d6c9abafaf87898e1eb4c929135782ea25bb0279703146455745391e63a"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithUtf8Path(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/%E1%88%B4", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/%E1%88%B4", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=8d6634c189aa8c75c2e51e106b6b5121bed103fdb351f7d7d4381c738823af74"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithDuplicateQuery(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/?foo=Zoo&foo=aha", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/?foo=Zoo&foo=aha", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=be7148d34ebccdc6423b19085378aa0bee970bdc61d144bd1a8c48c33079ab09"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithMisorderedQuery(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/?foo=b&foo=a", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/?foo=b&foo=a", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=feb926e49e382bec75c9d7dcb2a1b6dc8aa50ca43c25d2bc51143768c0875acc"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithUtf8Query(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://host.foo.com/?ሴ=bar", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("GET", "https://host.foo.com/?ሴ=bar", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=6fb359e9a05394cc7074e0feb42573a2601abc0c869a953e8c5c12e4e01f1a8c"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_PostRequest(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	setDefaultTime(input)
	input.Header.Add("ZOO", "zoobar")

	output, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=b7a95a52518abbca0964a999a880429ab734f35ebbf1235bd79a5de87756dc4a"},
		"Zoo":           []string{"zoobar"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_PostRequestWithCapitalizedHeaderValue(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	setDefaultTime(input)
	input.Header.Add("zoo", "ZOOBAR")

	output, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=273313af9d0c265c531e11db70bbd653f3ba074c1009239e8559d3987039cad7"},
		"Zoo":           []string{"ZOOBAR"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_PostRequestPhfft(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	setDefaultTime(input)
	input.Header.Add("p", "phfft")

	output, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;p, Signature=debf546796015d6f6ded8626f5ce98597c33b47b9164cf6b17b4642036fcb592"},
		"P":             []string{"phfft"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_PostRequestWithBody(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://host.foo.com/", strings.NewReader("foo=bar"))
	setDefaultTime(input)
	input.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	output, _ := http.NewRequest("POST", "https://host.foo.com/", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Content-Type":  []string{"application/x-www-form-urlencoded"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=5a15b22cf462f047318703b92e6f4f38884e4a7ab7b1d6426ca46a8bd1c26cbc"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_PostRequestWithQueryString(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://host.foo.com/?foo=bar", nil)
	setDefaultTime(input)

	output, _ := http.NewRequest("POST", "https://host.foo.com/?foo=bar", nil)
	output.Header = http.Header{
		"Host":          []string{"host.foo.com"},
		"Date":          []string{"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(defaultTime)

	testRequestSigner(t, defaultRequestSigner, input, output)
}

func TestAwsV4Signature_GetRequestWithSecurityToken(t *testing.T) {
	input, _ := http.NewRequest("GET", "https://ec2.us-east-2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15", nil)

	output, _ := http.NewRequest("GET", "https://ec2.us-east-2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15", nil)
	output.Header = http.Header{
		"Host":                 []string{"ec2.us-east-2.amazonaws.com"},
		"Authorization":        []string{"AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=631ea80cddfaa545fdadb120dc92c9f18166e38a5c47b50fab9fce476e022855"},
		"X-Amz-Date":           []string{"20200811T065522Z"},
		"X-Amz-Security-Token": []string{securityToken},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(secondDefaultTime)

	testRequestSigner(t, requestSignerWithToken, input, output)
}

func TestAwsV4Signature_PostRequestWithSecurityToken(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)

	output, _ := http.NewRequest("POST", "https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)
	output.Header = http.Header{
		"Authorization":        []string{"AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=73452984e4a880ffdc5c392355733ec3f5ba310d5e0609a89244440cadfe7a7a"},
		"Host":                 []string{"sts.us-east-2.amazonaws.com"},
		"X-Amz-Date":           []string{"20200811T065522Z"},
		"X-Amz-Security-Token": []string{securityToken},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(secondDefaultTime)

	testRequestSigner(t, requestSignerWithToken, input, output)
}

func TestAwsV4Signature_PostRequestWithSecurityTokenAndAdditionalHeaders(t *testing.T) {
	requestParams := "{\"KeySchema\":[{\"KeyType\":\"HASH\",\"AttributeName\":\"Id\"}],\"TableName\":\"TestTable\",\"AttributeDefinitions\":[{\"AttributeName\":\"Id\",\"AttributeType\":\"S\"}],\"ProvisionedThroughput\":{\"WriteCapacityUnits\":5,\"ReadCapacityUnits\":5}}"
	input, _ := http.NewRequest("POST", "https://dynamodb.us-east-2.amazonaws.com/", strings.NewReader(requestParams))
	input.Header.Add("Content-Type", "application/x-amz-json-1.0")
	input.Header.Add("x-amz-target", "DynamoDB_20120810.CreateTable")

	output, _ := http.NewRequest("POST", "https://dynamodb.us-east-2.amazonaws.com/", strings.NewReader(requestParams))
	output.Header = http.Header{
		"Authorization":        []string{"AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=fdaa5b9cc9c86b80fe61eaf504141c0b3523780349120f2bd8145448456e0385"},
		"Host":                 []string{"dynamodb.us-east-2.amazonaws.com"},
		"X-Amz-Date":           []string{"20200811T065522Z"},
		"Content-Type":         []string{"application/x-amz-json-1.0"},
		"X-Amz-Target":         []string{"DynamoDB_20120810.CreateTable"},
		"X-Amz-Security-Token": []string{securityToken},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(secondDefaultTime)

	testRequestSigner(t, requestSignerWithToken, input, output)
}

func TestAwsV4Signature_PostRequestWithAmzDateButNoSecurityToken(t *testing.T) {
	var requestSigner = &awsRequestSigner{
		RegionName: "us-east-2",
		AwsSecurityCredentials: awsSecurityCredentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
		},
	}

	input, _ := http.NewRequest("POST", "https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)

	output, _ := http.NewRequest("POST", "https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)
	output.Header = http.Header{
		"Authorization": []string{"AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=d095ba304919cd0d5570ba8a3787884ee78b860f268ed040ba23831d55536d56"},
		"Host":          []string{"sts.us-east-2.amazonaws.com"},
		"X-Amz-Date":    []string{"20200811T065522Z"},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(secondDefaultTime)

	testRequestSigner(t, requestSigner, input, output)
}

type testAwsServer struct {
	url                         string
	securityCredentialURL       string
	regionURL                   string
	regionalCredVerificationURL string

	Credentials map[string]string

	WriteRolename            func(http.ResponseWriter)
	WriteSecurityCredentials func(http.ResponseWriter)
	WriteRegion              func(http.ResponseWriter)
}

func createAwsTestServer(url, regionURL, regionalCredVerificationURL, rolename, region string, credentials map[string]string) *testAwsServer {
	server := &testAwsServer{
		url:                         url,
		securityCredentialURL:       fmt.Sprintf("%s/%s", url, rolename),
		regionURL:                   regionURL,
		regionalCredVerificationURL: regionalCredVerificationURL,
		Credentials:                 credentials,
		WriteRolename: func(w http.ResponseWriter) {
			w.Write([]byte(rolename))
		},
		WriteRegion: func(w http.ResponseWriter) {
			w.Write([]byte(region))
		},
	}

	server.WriteSecurityCredentials = func(w http.ResponseWriter) {
		jsonCredentials, _ := json.Marshal(server.Credentials)
		w.Write(jsonCredentials)
	}

	return server
}

func createDefaultAwsTestServer() *testAwsServer {
	return createAwsTestServer(
		"/latest/meta-data/iam/security-credentials",
		"/latest/meta-data/placement/availability-zone",
		"https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		"gcp-aws-role",
		"us-east-2b",
		map[string]string{
			"SecretAccessKey": secretAccessKey,
			"AccessKeyId":     accessKeyID,
			"Token":           securityToken,
		},
	)
}

func (server *testAwsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; p {
	case server.url:
		server.WriteRolename(w)
	case server.securityCredentialURL:
		server.WriteSecurityCredentials(w)
	case server.regionURL:
		server.WriteRegion(w)
	}
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(404)
	w.Write([]byte("Not Found"))
}

func (server *testAwsServer) getCredentialSource(url string) CredentialSource {
	return CredentialSource{
		EnvironmentID:               "aws1",
		URL:                         url + server.url,
		RegionURL:                   url + server.regionURL,
		RegionalCredVerificationURL: server.regionalCredVerificationURL,
	}
}

func getExpectedSubjectToken(url, region, accessKeyID, secretAccessKey, securityToken string) string {
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Add("x-goog-cloud-target-resource", testFileConfig.Audience)
	signer := &awsRequestSigner{
		RegionName: region,
		AwsSecurityCredentials: awsSecurityCredentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			SecurityToken:   securityToken,
		},
	}
	signer.SignRequest(req)

	result := awsRequest{
		URL:    url,
		Method: "POST",
		Headers: []awsRequestHeader{
			{
				Key:   "Authorization",
				Value: req.Header.Get("Authorization"),
			}, {
				Key:   "Host",
				Value: req.Header.Get("Host"),
			}, {
				Key:   "X-Amz-Date",
				Value: req.Header.Get("X-Amz-Date"),
			},
		},
	}

	if securityToken != "" {
		result.Headers = append(result.Headers, awsRequestHeader{
			Key:   "X-Amz-Security-Token",
			Value: securityToken,
		})
	}

	result.Headers = append(result.Headers, awsRequestHeader{
		Key:   "X-Goog-Cloud-Target-Resource",
		Value: testFileConfig.Audience,
	})

	str, _ := json.Marshal(result)
	return string(str)
}

func TestAwsCredential_BasicRequest(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	expected := getExpectedSubjectToken(
		"https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		"us-east-2",
		accessKeyID,
		secretAccessKey,
		securityToken,
	)

	if got, want := out, expected; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_BasicRequestWithoutSecurityToken(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	delete(server.Credentials, "Token")

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	expected := getExpectedSubjectToken(
		"https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		"us-east-2",
		accessKeyID,
		secretAccessKey,
		"",
	)

	if got, want := out, expected; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_BasicRequestWithEnv(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIDEXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"AWS_REGION":            "us-west-1",
	})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	expected := getExpectedSubjectToken(
		"https://sts.us-west-1.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		"us-west-1",
		"AKIDEXAMPLE",
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"",
	)

	if got, want := out, expected; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithBadVersion(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)
	tfc.CredentialSource.EnvironmentID = "aws3"

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	_, err := tfc.parse(context.Background())
	if err == nil {
		t.Fatalf("parse() should have failed")
	}
	if got, want := err.Error(), "oauth2/google: aws version '3' is not supported in the current build"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithNoRegionURL(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)
	tfc.CredentialSource.RegionURL = ""

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: unable to determine AWS region"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithBadRegionURL(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	server.WriteRegion = notFound

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: unable to retrieve AWS region - Not Found"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithMissingCredential(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	server.WriteSecurityCredentials = func(w http.ResponseWriter) {
		w.Write([]byte("{}"))
	}

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: missing AccessKeyId credential"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithIncompleteCredential(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	server.WriteSecurityCredentials = func(w http.ResponseWriter) {
		w.Write([]byte(`{"AccessKeyId":"FOOBARBAS"}`))
	}

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: missing SecretAccessKey credential"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithNoCredentialURL(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)
	tfc.CredentialSource.URL = ""

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: unable to determine the AWS metadata server security credentials endpoint"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithBadCredentialURL(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	server.WriteRolename = notFound

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: unable to retrieve AWS role name - Not Found"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}

func TestAwsCredential_RequestWithBadFinalCredentialURL(t *testing.T) {
	server := createDefaultAwsTestServer()
	ts := httptest.NewServer(server)
	server.WriteSecurityCredentials = notFound

	tfc := testFileConfig
	tfc.CredentialSource = server.getCredentialSource(ts.URL)

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("retrieveSubjectToken() should have failed")
	}

	if got, want := err.Error(), "oauth2/google: unable to retrieve AWS security credentials - Not Found"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}
