// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package endpoints provides constants for using OAuth2 to access various service.
package endpoints

import (
	"strings"

	"golang.org/x/oauth2"
)

// Amazon provides endpoint for using OAuth2 to access Amazon.
var Amazon = oauth2.Endpoint{
	AuthURL:  "https://www.amazon.com/ap/oa",
	TokenURL: "https://api.amazon.com/auth/o2/token",
}

// Bitbucket provides endpoint for using OAuth2 to access Bitbucket.
var Bitbucket = oauth2.Endpoint{
	AuthURL:  "https://bitbucket.org/site/oauth2/authorize",
	TokenURL: "https://bitbucket.org/site/oauth2/access_token",
}

// Cern provides endpoint for using OAuth2 to access Cern.
var Cern = oauth2.Endpoint{
	AuthURL:  "https://oauth.web.cern.ch/OAuth/Authorize",
	TokenURL: "https://oauth.web.cern.ch/OAuth/Token",
}

// Facebook provides endpoint for using OAuth2 to access Facebook.
var Facebook = oauth2.Endpoint{
	AuthURL:  "https://www.facebook.com/v3.2/dialog/oauth",
	TokenURL: "https://graph.facebook.com/v3.2/oauth/access_token",
}

// Foursquare provides endpoint for using OAuth2 to access Foursquare.
var Foursquare = oauth2.Endpoint{
	AuthURL:  "https://foursquare.com/oauth2/authorize",
	TokenURL: "https://foursquare.com/oauth2/access_token",
}

// Fitbit provides endpoint for using OAuth2 to access Fitbit.
var Fitbit = oauth2.Endpoint{
	AuthURL:  "https://www.fitbit.com/oauth2/authorize",
	TokenURL: "https://api.fitbit.com/oauth2/token",
}

// GitHub provides endpoint for using OAuth2 to access Github.
var GitHub = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

// GitLab provides endpoint for using OAuth2 to access Gitlab.
var GitLab = oauth2.Endpoint{
	AuthURL:  "https://gitlab.com/oauth/authorize",
	TokenURL: "https://gitlab.com/oauth/token",
}

// Google provides endpoint for using OAuth2 to access Google.
var Google = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://oauth2.googleapis.com/token",
}

// Heroku provides endpoint for using OAuth2 to access Heroku.
var Heroku = oauth2.Endpoint{
	AuthURL:  "https://id.heroku.com/oauth/authorize",
	TokenURL: "https://id.heroku.com/oauth/token",
}

// HipChat provides endpoint for using OAuth2 to access HipChat.
var HipChat = oauth2.Endpoint{
	AuthURL:  "https://www.hipchat.com/users/authorize",
	TokenURL: "https://api.hipchat.com/v2/oauth/token",
}

// Instagram provides endpoint for using OAuth2 to access Instagram.
var Instagram = oauth2.Endpoint{
	AuthURL:  "https://api.instagram.com/oauth/authorize",
	TokenURL: "https://api.instagram.com/oauth/access_token",
}

// Kakao provides endpoint for using OAuth2 to access Kakao.
var Kakao = oauth2.Endpoint{
	AuthURL:  "https://kauth.kakao.com/oauth/authorize",
	TokenURL: "https://kauth.kakao.com/oauth/token",
}

// Linkedin provides endpoint for using OAuth2 to access Linkedin.
var Linkedin = oauth2.Endpoint{
	AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
	TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
}

// Mailchimp provides endpoint for using OAuth2 to access Mailchimp.
var Mailchimp = oauth2.Endpoint{
	AuthURL:  "https://login.mailchimp.com/oauth2/authorize",
	TokenURL: "https://login.mailchimp.com/oauth2/token",
}

// Mailru provides endpoint for using OAuth2 to access Mailru.
var Mailru = oauth2.Endpoint{
	AuthURL:  "https://o2.mail.ru/login",
	TokenURL: "https://o2.mail.ru/token",
}

// MediaMath provides endpoint for using OAuth2 to access MediaMath.
var MediaMath = oauth2.Endpoint{
	AuthURL:  "https://api.mediamath.com/oauth2/v1.0/authorize",
	TokenURL: "https://api.mediamath.com/oauth2/v1.0/token",
}

// MediamathSandbox provides endpoint for using OAuth2 to access Mediamath Sandbox.
var MediamathSandbox = oauth2.Endpoint{
	AuthURL:  "https://t1sandbox.mediamath.com/oauth2/v1.0/authorize",
	TokenURL: "https://t1sandbox.mediamath.com/oauth2/v1.0/token",
}

// Microsoft provides endpoint for using OAuth2 to access Microsoft.
var Microsoft = oauth2.Endpoint{
	AuthURL:  "https://login.live.com/oauth20_authorize.srf",
	TokenURL: "https://login.live.com/oauth20_token.srf",
}

// Nokiahealth provides endpoint for using OAuth2 to access Nokiahealth.
var Nokiahealth = oauth2.Endpoint{
	AuthURL:  "https://account.health.nokia.com/oauth2_user/authorize2",
	TokenURL: "https://account.health.nokia.com/oauth2/token",
}

// Odnoklassniki provides endpoint for using OAuth2 to access Odnoklassniki.
var Odnoklassniki = oauth2.Endpoint{
	AuthURL:  "https://www.odnoklassniki.ru/oauth/authorize",
	TokenURL: "https://api.odnoklassniki.ru/oauth/token.do",
}

// Paypal provides endpoint for using OAuth2 to access Paypal.
var Paypal = oauth2.Endpoint{
	AuthURL:  "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize",
	TokenURL: "https://api.paypal.com/v1/identity/openidconnect/tokenservice",
}

// PaypalSandbox provides endpoint for using OAuth2 to access Paypal Sandbox.
var PaypalSandbox = oauth2.Endpoint{
	AuthURL:  "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize",
	TokenURL: "https://api.sandbox.paypal.com/v1/identity/openidconnect/tokenservice",
}

// Slack provides endpoint for using OAuth2 to access Slack.
var Slack = oauth2.Endpoint{
	AuthURL:  "https://slack.com/oauth/authorize",
	TokenURL: "https://slack.com/api/oauth.access",
}

// Spotify provides endpoint for using OAuth2 to access Spotify.
var Spotify = oauth2.Endpoint{
	AuthURL:  "https://accounts.spotify.com/authorize",
	TokenURL: "https://accounts.spotify.com/api/token",
}

// Stackoverflow provides endpoint for using OAuth2 to access Stackoverflow.
var Stackoverflow = oauth2.Endpoint{
	AuthURL:  "https://stackoverflow.com/oauth",
	TokenURL: "https://stackoverflow.com/oauth/access_token",
}

// Twitch provides endpoint for using OAuth2 to access Twitch.
var Twitch = oauth2.Endpoint{
	AuthURL:  "https://id.twitch.tv/oauth2/authorize",
	TokenURL: "https://id.twitch.tv/oauth2/token",
}

// Uber provides endpoint for using OAuth2 to access Uber.
var Uber = oauth2.Endpoint{
	AuthURL:  "https://login.uber.com/oauth/v2/authorize",
	TokenURL: "https://login.uber.com/oauth/v2/token",
}

// Vk provides endpoint for using OAuth2 to access Vk.
var Vk = oauth2.Endpoint{
	AuthURL:  "https://oauth.vk.com/authorize",
	TokenURL: "https://oauth.vk.com/access_token",
}

// Yahoo provides endpoint for using OAuth2 to access Yahoo.
var Yahoo = oauth2.Endpoint{
	AuthURL:  "https://api.login.yahoo.com/oauth2/request_auth",
	TokenURL: "https://api.login.yahoo.com/oauth2/get_token",
}

// Yandex provides endpoint for using OAuth2 to access Yandex.
var Yandex = oauth2.Endpoint{
	AuthURL:  "https://oauth.yandex.com/authorize",
	TokenURL: "https://oauth.yandex.com/token",
}

// AzureAD returns a new oauth2.Endpoint for the given tenant at Azure Active Directory.
// If tenant is empty, it uses the tenant called `common`.
//
// For more information see:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
func AzureAD(tenant string) oauth2.Endpoint {
	if tenant == "" {
		tenant = "common"
	}
	return oauth2.Endpoint{
		AuthURL:  "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
	}
}

// HipChatServer returns a new oauth2.Endpoint for a HipChat Server instance
// running on the given domain or host.
func HipChatServer(host string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  "https://" + host + "/users/authorize",
		TokenURL: "https://" + host + "/v2/oauth/token",
	}
}

// AWSCognito returns a new oauth2.Endpoint for the supplied AWS Cognito domain which is
// linked to your Cognito User Pool.
//
// Example domain: https://testing.auth.us-east-1.amazoncognito.com
//
// For more information see:
// https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html
// https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html
func AWSCognito(domain string) oauth2.Endpoint {
	domain = strings.TrimRight(domain, "/")
	return oauth2.Endpoint{
		AuthURL:  domain + "/oauth2/authorize",
		TokenURL: domain + "/oauth2/token",
	}
}
