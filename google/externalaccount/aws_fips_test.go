// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"net/http"
	"strings"
	"testing"
)

func TestAWSv4Signature_PostRequestFipsWithSecurityToken(t *testing.T) {
	defer func() {
		now = setTime(defaultTime)
	}()
	now = setTime(secondDefaultTime)

	req, err := http.NewRequest("POST", "https://sts-fips.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed across baseline setup: %v", err)
	}

	err = requestSignerWithToken.SignRequest(req)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	expectedHeaderMap := map[string]string{
		"Authorization":        "AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=dc64d2d5b33786e97de10de5a82428f1e79cbc69d6ec3d450780f29b20eaa43f",
		"x-amz-date":           "20200811T065522Z",
		"x-amz-security-token": securityToken,
	}

	for k, v := range expectedHeaderMap {
		if got := req.Header.Get(k); got != v {
			t.Errorf("Header %q = %q, want %q", k, got, v)
		}
	}
	if req.Host != "sts-fips.us-east-2.amazonaws.com" {
		t.Errorf("Host = %q, want %q", req.Host, "sts-fips.us-east-2.amazonaws.com")
	}
}
