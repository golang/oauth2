// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"
)

// DeviceAuthResponse describes a successful RFC 8628 Device Authorization Response
// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
//
// This type is a mirror of oauth2.DeviceAuthResponse, with the only difference
// being that in this struct `expires_in` isn't mapped to a timestamp. It solely
// exists to break an otherwise-circular dependency. Other internal packages should
// convert this DeviceAuthResponse into an oauth2.DeviceAuthResponse before use.
type DeviceAuthResponse struct {
	// DeviceCode
	DeviceCode string `json:"device_code"`
	// UserCode is the code the user should enter at the verification uri
	UserCode string `json:"user_code"`
	// VerificationURI is where user should enter the user code
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete (if populated) includes the user code in the verification URI. This is typically shown to the user in non-textual form, such as a QR code.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// Expiry is when the device code and user code expire
	Expiry int64 `json:"expires_in,omitempty"`
	// Interval is the duration in seconds that Poll should wait between requests
	Interval int64 `json:"interval,omitempty"`
}

func RetrieveDeviceAuth(ctx context.Context, clientID, clientSecret, deviceAuthURL string, v url.Values, authStyle AuthStyle, styleCache *AuthStyleCache) (*DeviceAuthResponse, error) {
	needsAuthStyleProbe := authStyle == AuthStyleUnknown
	if needsAuthStyleProbe {
		if style, ok := styleCache.lookupAuthStyle(deviceAuthURL); ok {
			authStyle = style
			needsAuthStyleProbe = false
		} else {
			authStyle = AuthStyleInHeader // the first way we'll try
		}
	}

	req, err := NewRequestWithClientAuthn("POST", deviceAuthURL, clientID, clientSecret, v, authStyle)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	t := time.Now()
	r, err := ContextClient(ctx).Do(req)

	if err != nil && needsAuthStyleProbe {
		// If we get an error, assume the server wants the
		// clientID & clientSecret in a different form.
		authStyle = AuthStyleInParams // the second way we'll try
		req, _ := NewRequestWithClientAuthn("POST", deviceAuthURL, clientID, clientSecret, v, authStyle)
		r, err = ContextClient(ctx).Do(req)
	}
	if needsAuthStyleProbe && err == nil {
		styleCache.setAuthStyle(deviceAuthURL, authStyle)
	}

	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot auth device: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	da := &DeviceAuthResponse{}
	err = json.Unmarshal(body, &da)
	if err != nil {
		return nil, fmt.Errorf("unmarshal %s", err)
	}

	if da.Expiry != 0 {
		// Make a small adjustment to account for time taken by the request
		da.Expiry = da.Expiry + int64(t.Nanosecond())
	}
	return da, nil
}
