// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"
)

const (
	executableSupportedMaxVersion = 1
	defaultTimeout                = 30 * time.Second
)

func missingFieldError(field string) error {
	return fmt.Errorf("oauth2/google: response missing `%v` field", field)
}

func jsonParsingError() error {
	return errors.New("oauth2/google: unable to parse response JSON")
}

func malformedFailureError() error {
	return errors.New("oauth2/google: response must include `error` and `message` fields when unsuccessful")
}

func userDefinedError(code, message string) error {
	return fmt.Errorf("oauth2/google: executable returned unsuccessful response: (%v) %v", code, message)
}

func unsupportedVersionError(version int) error {
	return fmt.Errorf("oauth2/google: executable returned unsupported version: %v", version)
}

func tokenExpiredError() error {
	return errors.New("oauth2/google: the token returned by the executable is expired")
}

func tokenTypeError() error {
	return errors.New("oauth2/google: executable returned unsupported token type")
}

func timeoutError() error {
	return errors.New("oauth2/google: executable command timed out")
}

func exitCodeError(exitCode int) error {
	return fmt.Errorf("oauth2/google: executable command failed with exit code %v", exitCode)
}

func executableError(err error) error {
	return fmt.Errorf("oauth2/google: executable command failed: %v", err.Error())
}

func executablesDisallowedError() error {
	return errors.New("Executables need to be explicitly allowed (set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES to '1') to run")
}

// baseEnv is an alias of os.Environ used for testing
var baseEnv = os.Environ

// runCommand is basically an alias of exec.CommandContext for testing.
var runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command)
	cmd.Env = env

	response, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}

type executableCredentialSource struct {
	Command    string
	Timeout    time.Duration
	OutputFile string
	ctx        context.Context
	config     *Config
}

// CreateExecutableCredential creates an executableCredentialSource given an ExecutableConfig.
// It also performs defaulting and type conversions.
func CreateExecutableCredential(ec ExecutableConfig, config *Config, ctx context.Context) (result executableCredentialSource) {
	result.Command = ec.Command
	if ec.TimeoutMillis == 0 {
		result.Timeout = defaultTimeout
	} else {
		result.Timeout = time.Duration(ec.TimeoutMillis) * time.Millisecond
	}
	result.OutputFile = ec.OutputFile
	result.ctx = ctx
	result.config = config
	return
}

type executableResponse struct {
	Version        *int    `json:"version,omitempty"`
	Success        *bool   `json:"success,omitempty"`
	TokenType      *string `json:"token_type,omitempty"`
	ExpirationTime *int64  `json:"expiration_time,omitempty"`
	IdToken        *string `json:"id_token,omitempty"`
	SamlResponse   *string `json:"saml_response,omitempty"`
	Code           string  `json:"code,omitempty"`
	Message        string  `json:"message,omitempty"`
}

func parseSubjectToken(response []byte) (string, error) {
	var result executableResponse
	if err := json.Unmarshal(response, &result); err != nil {
		return "", jsonParsingError()
	}

	if result.Version == nil {
		return "", missingFieldError("version")
	}

	if result.Success == nil {
		return "", missingFieldError("success")
	}

	if !*result.Success {
		if result.Code == "" || result.Message == "" {
			return "", malformedFailureError()
		}
		return "", userDefinedError(result.Code, result.Message)
	}

	if *result.Version > executableSupportedMaxVersion {
		return "", unsupportedVersionError(*result.Version)
	}

	if result.ExpirationTime == nil {
		return "", missingFieldError("expiration_time")
	}

	if result.TokenType == nil {
		return "", missingFieldError("token_type")
	}

	if *result.ExpirationTime < now().Unix() {
		return "", tokenExpiredError()
	}

	if *result.TokenType == "urn:ietf:params:oauth:token-type:jwt" || *result.TokenType == "urn:ietf:params:oauth:token-type:id_token" {
		if result.IdToken == nil {
			return "", missingFieldError("id_token")
		}
		return *result.IdToken, nil
	}

	if *result.TokenType == "urn:ietf:params:oauth:token-type:saml2" {
		if result.SamlResponse == nil {
			return "", missingFieldError("saml_response")
		}
		return *result.SamlResponse, nil
	}

	return "", tokenTypeError()
}

func (cs executableCredentialSource) subjectToken() (string, error) {
	if token, ok := cs.getTokenFromOutputFile(); ok {
		return token, nil
	}

	return cs.getTokenFromExecutableCommand()
}

func (cs executableCredentialSource) getTokenFromOutputFile() (string, bool) {
	// TODO
	return "", false
}

func (cs executableCredentialSource) getEnvironment() []string {
	result := baseEnv()
	for k, v := range cs.getNewEnvironmentVariables() {
		result = append(result, fmt.Sprintf("%v=%v", k, v))
	}
	return result
}

var serviceAccountImpersonationCompiler = regexp.MustCompile("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/(.*@.*):generateAccessToken")

func (cs executableCredentialSource) getNewEnvironmentVariables() map[string]string {
	result := map[string]string{
		"GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE":   cs.config.Audience,
		"GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE": cs.config.SubjectTokenType,
	}

	if cs.config.ServiceAccountImpersonationURL != "" {
		matches := serviceAccountImpersonationCompiler.FindStringSubmatch(cs.config.ServiceAccountImpersonationURL)
		if matches != nil {
			result["GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"] = matches[1]
		}
	}

	result["GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"] = "0"

	if cs.OutputFile != "" {
		result["GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"] = cs.OutputFile
	}

	return result
}

func (cs executableCredentialSource) getTokenFromExecutableCommand() (string, error) {
	// For security reasons, we need our consumers to set this environment variable to allow executables to be run.
	if getenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES") != "1" {
		return "", executablesDisallowedError()
	}

	ctx, cancel := context.WithDeadline(cs.ctx, now().Add(cs.Timeout))
	defer cancel()

	if output, err := runCommand(ctx, cs.Command, cs.getEnvironment()); err != nil {
		if err == context.DeadlineExceeded {
			return "", timeoutError()
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", exitCodeError(exitError.ExitCode())
		}
		return "", executableError(err)
	} else {
		return parseSubjectToken(output)
	}
}
