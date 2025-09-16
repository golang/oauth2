package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/internal"
)

// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = "access_denied"
	errExpiredToken         = "expired_token"
)

// DeviceAuthResponse describes a successful RFC 8628 Device Authorization Response
// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
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
	Expiry time.Time `json:"expires_in,omitempty"`
	// Interval is the duration in seconds that Poll should wait between requests
	Interval int64 `json:"interval,omitempty"`
}

func (d DeviceAuthResponse) MarshalJSON() ([]byte, error) {
	type Alias DeviceAuthResponse
	var expiresIn int64
	if !d.Expiry.IsZero() {
		expiresIn = int64(time.Until(d.Expiry).Seconds())
	}
	return json.Marshal(&struct {
		ExpiresIn int64 `json:"expires_in,omitempty"`
		*Alias
	}{
		ExpiresIn: expiresIn,
		Alias:     (*Alias)(&d),
	})

}

func (c *DeviceAuthResponse) UnmarshalJSON(data []byte) error {
	type Alias DeviceAuthResponse
	aux := &struct {
		ExpiresIn int64 `json:"expires_in"`
		// workaround misspelling of verification_uri
		VerificationURL string `json:"verification_url"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ExpiresIn != 0 {
		c.Expiry = time.Now().UTC().Add(time.Second * time.Duration(aux.ExpiresIn))
	}
	if c.VerificationURI == "" {
		c.VerificationURI = aux.VerificationURL
	}
	return nil
}

// DeviceAuth returns a device auth struct which contains a device code
// and authorization information provided for users to enter on another device.
func (c *Config) DeviceAuth(ctx context.Context, opts ...AuthCodeOption) (*DeviceAuthResponse, error) {
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
	v := url.Values{
		"client_id": {c.ClientID},
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	return retrieveDeviceAuth(ctx, c, v)
}

// deviceAuthFromInternal maps an *internal.DeviceAuthResponse struct into
// a *DeviceAuthResponse struct.
func deviceAuthFromInternal(da *internal.DeviceAuthResponse) *DeviceAuthResponse {
	if da == nil {
		return nil
	}
	return &DeviceAuthResponse{
		DeviceCode:              da.DeviceCode,
		UserCode:                da.UserCode,
		VerificationURI:         da.VerificationURI,
		VerificationURIComplete: da.VerificationURIComplete,
		Expiry:                  time.Now().UTC().Add(time.Second * time.Duration(da.Expiry)),
		Interval:                da.Interval,
	}
}

// retrieveDeviceAuth takes a *Config and uses that to retrieve an *internal.DeviceAuthResponse.
// This response is then mapped from *internal.DeviceAuthResponse into an *oauth2.DeviceAuthResponse which is returned along
// with an error.
func retrieveDeviceAuth(ctx context.Context, c *Config, v url.Values) (*DeviceAuthResponse, error) {
	if c.Endpoint.DeviceAuthURL == "" {
		return nil, errors.New("endpoint missing DeviceAuthURL")
	}

	da, err := internal.RetrieveDeviceAuth(ctx, c.ClientID, c.ClientSecret, c.Endpoint.DeviceAuthURL, v, internal.AuthStyle(c.Endpoint.AuthStyle), c.authStyleCache.Get())
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*RetrieveError)(rErr)
		}
		return nil, err
	}
	dar := deviceAuthFromInternal(da)

	return dar, err
}

// DeviceAccessToken polls the server to exchange a device code for a token.
func (c *Config) DeviceAccessToken(ctx context.Context, da *DeviceAuthResponse, opts ...AuthCodeOption) (*Token, error) {
	if !da.Expiry.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, da.Expiry)
		defer cancel()
	}

	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
	v := url.Values{
		"client_id":   {c.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	for _, opt := range opts {
		opt.setValue(v)
	}

	// "If no value is provided, clients MUST use 5 as the default."
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
	interval := da.Interval
	if interval == 0 {
		interval = 5
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			tok, err := retrieveToken(ctx, c, v)
			if err == nil {
				return tok, nil
			}

			e, ok := err.(*RetrieveError)
			if !ok {
				return nil, err
			}
			switch e.ErrorCode {
			case errSlowDown:
				// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
				// "the interval MUST be increased by 5 seconds for this and all subsequent requests"
				interval += 5
				ticker.Reset(time.Duration(interval) * time.Second)
			case errAuthorizationPending:
				// Do nothing.
			case errAccessDenied, errExpiredToken:
				fallthrough
			default:
				return tok, err
			}
		}
	}
}
