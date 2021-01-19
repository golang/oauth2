// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package externalaccount

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// A utility class to sign http requests using a AWS V4 signature
type RequestSigner struct {
	RegionName             string
	AwsSecurityCredentials map[string]string
	debugTimestamp         time.Time
}

func NewRequestSigner(regionName string, awsSecurityCredentials map[string]string) *RequestSigner {
	return &RequestSigner{
		RegionName:             regionName,
		AwsSecurityCredentials: awsSecurityCredentials,
	}
}

// AWS Signature Version 4 signing algorithm identifier.
const awsAlgorithm = "AWS4-HMAC-SHA256"

// The termination string for the AWS credential scope value as defined in
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
const awsRequestType = "aws4_request"

// The AWS authorization header name for the security session token if available.
const awsSecurityTokenHeader = "x-amz-security-token"

// The AWS authorization header name for the auto-generated date.
const awsDateHeader = "x-amz-date"

const awsTimeFormatLong = "20060102T150405Z"
const awsTimeFormatShort = "20060102"

func getSha256(input []byte) string {
	hash := sha256.New()
	hash.Write(input)
	return hex.EncodeToString(hash.Sum(nil))
}

func getHmacSha256(key, input []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(input)
	return hash.Sum(nil)
}

func canonicalPath(req *http.Request) string {
	result := req.URL.EscapedPath()
	if result == "" {
		return "/"
	}
	return path.Clean(result)
}

func canonicalQuery(req *http.Request) string {
	queryValues := req.URL.Query()
	for queryKey := range queryValues {
		sort.Strings(queryValues[queryKey])
	}
	return queryValues.Encode()
}

func canonicalHeaders(req *http.Request) (string, string) {
	// Header keys need to be sorted alphabetically.
	var headers []string
	lowerCaseHeaders := make(http.Header)
	for k, v := range req.Header {
		k := strings.ToLower(k)
		if _, ok := lowerCaseHeaders[k]; ok {
			// include additional values
			lowerCaseHeaders[k] = append(lowerCaseHeaders[k], v...)
		} else {
			headers = append(headers, k)
			lowerCaseHeaders[k] = v
		}
	}
	sort.Strings(headers)

	var fullHeaders []string
	for _, header := range headers {
		headerValue := strings.Join(lowerCaseHeaders[header], ",")
		fullHeaders = append(fullHeaders, header+":"+headerValue+"\n")
	}

	return strings.Join(headers, ";"), strings.Join(fullHeaders, "")
}

func requestDataHash(req *http.Request) string {
	requestData := []byte{}
	if req.Body != nil {
		requestBody, _ := req.GetBody()
		requestData, _ = ioutil.ReadAll(requestBody)
	}

	return getSha256(requestData)
}

func requestHost(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

func canonicalRequest(req *http.Request, canonicalHeaderColumns, canonicalHeaderData string) string {
	return strings.Join([]string{
		req.Method,
		canonicalPath(req),
		canonicalQuery(req),
		canonicalHeaderData,
		canonicalHeaderColumns,
		requestDataHash(req),
	}, "\n")
}

func (rs *RequestSigner) SignedRequest(req *http.Request) *http.Request {
	timestamp := rs.debugTimestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	signedRequest := req.Clone(req.Context())

	signedRequest.Header.Add("host", requestHost(req))

	securityToken, ok := rs.AwsSecurityCredentials["security_token"]
	if ok {
		signedRequest.Header.Add("x-amz-security-token", securityToken)
	}

	if signedRequest.Header.Get("date") == "" {
		signedRequest.Header.Add("x-amz-date", timestamp.Format(awsTimeFormatLong))
	}

	signedRequest.Header.Set("Authorization", rs.generateAuthentication(signedRequest, timestamp))

	return signedRequest
}

func (rs *RequestSigner) generateAuthentication(req *http.Request, timestamp time.Time) string {
	canonicalHeaderColumns, canonicalHeaderData := canonicalHeaders(req)

	dateStamp := timestamp.Format(awsTimeFormatShort)
	serviceName := strings.Split(requestHost(req), ".")[0]

	credentialScope := strings.Join([]string{
		dateStamp, rs.RegionName, serviceName, awsRequestType,
	}, "/")

	stringToSign := strings.Join([]string{
		awsAlgorithm,
		timestamp.Format(awsTimeFormatLong),
		credentialScope,
		getSha256([]byte(canonicalRequest(req, canonicalHeaderColumns, canonicalHeaderData))),
	}, "\n")

	signingKey := []byte("AWS4" + rs.AwsSecurityCredentials["secret_access_key"])
	for _, signingInput := range []string{
		dateStamp, rs.RegionName, serviceName, awsRequestType, stringToSign,
	} {
		signingKey = getHmacSha256(signingKey, []byte(signingInput))
	}

	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", awsAlgorithm, rs.AwsSecurityCredentials["access_key_id"], credentialScope, canonicalHeaderColumns, hex.EncodeToString(signingKey))
}
