package microsoft

import "golang.org/x/oauth2"

// LiveConnectEndpoint is Windows's Live ID OAuth 2.0 endpoint.
var LiveConnectEndpoint = oauth2.Endpoint{
	AuthURL:  "https://login.live.com/oauth20_authorize.srf",
	TokenURL: "https://login.live.com/oauth20_token.srf",
}
