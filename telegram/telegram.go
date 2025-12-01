package telegram

import "golang.org/x/oauth2"

var Endpoint = oauth2.Endpoint{
	AuthURL: "https://oauth.telegram.org/auth",
}

func SetTelegramAuthStyle(botID string, originDomain string, redirectURL string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("bot_id", botID),
		oauth2.SetAuthURLParam("origin", originDomain),
		oauth2.SetAuthURLParam("return_to", redirectURL),
		oauth2.SetAuthURLParam("request_access", "write&embed=0"),
	}
}
