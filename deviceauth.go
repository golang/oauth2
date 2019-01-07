package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/context/ctxhttp"
)

const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = "access_denied"
	errExpiredToken         = "expired_token"
)

type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri,verification_url"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
	raw                     map[string]interface{}
}

func retrieveDeviceAuth(ctx context.Context, c *Config, v url.Values) (*DeviceAuth, error) {
	req, err := http.NewRequest("POST", c.Endpoint.DeviceAuthURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := ctxhttp.Do(ctx, nil, req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot auth device: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	da := &DeviceAuth{}
	err = json.Unmarshal(body, &da)
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(body, &da.raw)

	// Azure AD supplies verification_url instead of verification_uri
	if da.VerificationURI == "" {
		da.VerificationURI, _ = da.raw["verification_url"].(string)
	}

	return da, nil
}

func parseError(err error) string {
	e, ok := err.(*RetrieveError)
	if ok {
		eResp := make(map[string]string)
		_ = json.Unmarshal(e.Body, &eResp)
		return eResp["error"]
	}
	return ""
}
