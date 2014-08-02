package jws_test

import (
	"testing"

	. "github.com/golang/oauth2/jws"
)

func TestDecode(t *testing.T) {
	// example JWT taken from https://developers.google.com/wallet/digital/docs/jsreference
	jws := "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
		"eyJleHAiOiAxMzA5OTkxNzY0LCAiYXVkIjogImdvb2cucGF5bWVudHMuaW5hcHAuYnV5SXRlbSIsICJpc3MiOiAiMTA4NzM2NjAzNTQ2MjAwOTQ3MTYiLCAic2VsbGVyRGF0YSI6ICJfc2VsbGVyX2RhdGFfIiwgIml0ZW1EZXNjcmlwdGlvbiI6ICJUaGUgc2FmZXRpZXN0IHdheSB0byBkaXNwbGF5IHlvdXIgZmxhaXIiLCAiaXRlbVByaWNlIjogIjMuOTkiLCAiaXNvQ3VycmVuY3lDb2RlIjogIlVTRCIsICJpYXQiOiAxMzA5OTkxMTY0LCAiaXRlbU5hbWUiOiAiU2FmZXR5bW91c2UgUGF0Y2gifQ." +
		"E1VH0T9DvQn4GdCjyVavnlurpx0iklQXlqeI1_tAMa8"

	claimSet, err := Decode(jws)
	if err != nil {
		t.Fatalf("failed to decode JWT: %v", err)
	}
	if claimSet.Iss != "10873660354620094716" {
		t.Fatalf("received iss = %v; want 10873660354620094716", claimSet.Iss)
	}
	if claimSet.Aud != "goog.payments.inapp.buyItem" {
		t.Fatalf("received aud = %v; want goog.payments.inapp.buyItem", claimSet.Aud)
	}
	if claimSet.Exp != 1309991764 {
		t.Fatalf("received exp = %v; want 1309991764", claimSet.Exp)
	}
	if claimSet.Iat != 1309991164 {
		t.Fatalf("received iat = %v; want 1309991164", claimSet.Iat)
	}
}
