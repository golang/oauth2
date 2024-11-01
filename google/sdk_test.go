// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"fmt"
	"testing"
	"time"
)

const mockResponseTemplate = `{
    "credential": {
      "access_token": %q,
      "token_expiry": %q
    }
}`

func TestSDKConfig(t *testing.T) {
	var helperCallCount int
	mockTokenFormat := "Token #%d"
	mockHelper := func() []byte {
		token := fmt.Sprintf(mockTokenFormat, helperCallCount)
		helperCallCount += 1
		return []byte(fmt.Sprintf(mockResponseTemplate, token, time.Now().Format(time.RFC3339)))
	}
	for i := 0; i < 10; i++ {
		tok, err := parseConfigHelperResp(mockHelper())
		if err != nil {
			t.Errorf("Unexpected error parsing a mock config helper response: %v", err)
		} else if got, want := tok.AccessToken, fmt.Sprintf(mockTokenFormat, i); got != want {
			t.Errorf("Got access token of %q; wanted %q", got, want)
		}
	}

	badJSON := []byte(`Not really a JSON response`)
	if tok, err := parseConfigHelperResp(badJSON); err == nil {
		t.Errorf("unexpected parsing result for an malformed helper response: got %v", tok)
	}

	badTimestamp := []byte(fmt.Sprintf(mockResponseTemplate, "Fake Token", "The time at which it expires"))
	if tok, err := parseConfigHelperResp(badTimestamp); err == nil {
		t.Errorf("unexpected parsing result for a helper response with a bad expiry timestamp: got %v", tok)
	}
}
