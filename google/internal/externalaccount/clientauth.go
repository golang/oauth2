package externalaccount

import (
	"encoding/base64"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

// ClientAuthentication represents an OAuth client ID and secret and the mechanism for passing these credentials as stated in rfc6749#2.3.1.
type ClientAuthentication struct {
	//AuthStyle can be either basic or request-body
	AuthStyle    oauth2.AuthStyle
	ClientID     string
	ClientSecret string
}

func (c *ClientAuthentication) InjectAuthentication(values url.Values, headers http.Header) {
	if c.ClientID == "" || c.ClientSecret == "" || values == nil || headers == nil {
		return
	}

	switch c.AuthStyle {
	case oauth2.AuthStyleInHeader:
		plainHeader := c.ClientID + ":" + c.ClientSecret
		headers.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(plainHeader)))
	case oauth2.AuthStyleInParams:
		values.Set("client_id", c.ClientID)
		values.Set("client_secret", c.ClientSecret)
	case oauth2.AuthStyleAutoDetect:
		values.Set("client_id", c.ClientID)
		values.Set("client_secret", c.ClientSecret)
	default:
		values.Set("client_id", c.ClientID)
		values.Set("client_secret", c.ClientSecret)
	}

	return
}
