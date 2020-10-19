package externalaccount

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func ExchangeToken(endpoint string, request *STSTokenExchangeRequest, authentication ClientAuthentication, headers http.Header, options map[string]interface{}) (*STSTokenExchangeResponse, error) {

	client := &http.Client{}

	data := url.Values{}
	data.Set("audience", request.Audience)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("subject_token_type", request.SubjectTokenType)
	data.Set("subject_token", request.SubjectToken)
	data.Set("scope", strings.Join(request.Scope, " "))

	authentication.InjectAuthentication(&data, &headers)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Errorf("oauth2/google: failed to properly build http request")
	}
	for key, _ := range headers {
		for _, val := range headers.Values(key) {
			req.Header.Add(key, val)
		}
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("oauth2/google: invalid response from Secure Token Server: #{err}")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("oauth2/google: invalid body in Secute Token Server response: #{err}")
	}
	var stsResp STSTokenExchangeResponse
	err = json.Unmarshal(body, &stsResp)
	if err != nil {
		fmt.Println(err)
	}
	return &stsResp, nil
}

type STSTokenExchangeRequest struct {
	ActingParty struct {
		ActorToken     string
		ActorTokenType string
	}
	GrantType          string
	Resource           string
	Audience           string
	Scope              []string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
}

type STSTokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`
}
