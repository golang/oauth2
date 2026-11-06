// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"net/http"
	"testing"
)

func TestAWSv4Signature_PostRequestFipsWithSecurityToken(t *testing.T) {
	input, _ := http.NewRequest("POST", "https://sts-fips.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)

	output, _ := http.NewRequest("POST", "https://sts-fips.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)
	output.Header = http.Header{
		"Authorization":        []string{"AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=dc64d2d5b33786e97de10de5a82428f1e79cbc69d6ec3d450780f29b20eaa43f"},
		"Host":                 []string{"sts-fips.us-east-2.amazonaws.com"},
		"X-Amz-Date":           []string{"20200811T065522Z"},
		"X-Amz-Security-Token": []string{securityToken},
	}

	oldNow := now
	defer func() { now = oldNow }()
	now = setTime(secondDefaultTime)

	testRequestSigner(t, requestSignerWithToken, input, output)
}
