package externalaccount

import "golang.org/x/oauth2"

// ClientAuthentication represents an OAuth client ID and secret and the mechanism for passing these credentials as stated in rfc6749#2.3.1
type ClientAuthentication struct {
	//Can be either basic or request-body
	AuthStyle oauth2.AuthStyle
	ClientID string
	ClientSecret string
}


