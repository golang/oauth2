// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func Bool(b bool) *bool {
	return &b
}

func Int(i int) *int {
	return &i
}

func Int64(i int64) *int64 {
	return &i
}

func String(s string) *string {
	return &s
}

func TestCreateExecutableCredential(t *testing.T) {
	ec := ExecutableConfig{
		Command:       "blarg",
		TimeoutMillis: Int(50000),
	}

	ecs, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}
	if ecs.Command != "blarg" {
		t.Errorf("ecs.Command got %v but want %v", ecs.Command, "blarg")
	}
	if ecs.Timeout != 50000*time.Millisecond {
		t.Errorf("ecs.Timeout got %v but want %v", ecs.Timeout, 50000*time.Millisecond)
	}
}

func TestCreateExecutableCredential_WithoutTimeout(t *testing.T) {
	ec := ExecutableConfig{
		Command: "blarg",
	}

	ecs, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}
	if ecs.Command != "blarg" {
		t.Errorf("ecs.Command got %v but want %v", ecs.Command, "blarg")
	}
	if ecs.Timeout != defaultTimeout {
		t.Errorf("ecs.Timeout got %v but want %v", ecs.Timeout, 30000*time.Millisecond)
	}
}

func TestCreateExectuableCredential_WithoutCommand(t *testing.T) {
	ec := ExecutableConfig{}

	_, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), commandMissingError().Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestCreateExectuableCredential_TimeoutTooLow(t *testing.T) {
	ec := ExecutableConfig{
		Command:       "blarg",
		TimeoutMillis: Int(4999),
	}

	_, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), timeoutRangeError().Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestCreateExectuableCredential_TimeoutLow(t *testing.T) {
	ec := ExecutableConfig{
		Command:       "blarg",
		TimeoutMillis: Int(5000),
	}

	_, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}
}

func TestCreateExectuableCredential_TimeoutHigh(t *testing.T) {
	ec := ExecutableConfig{
		Command:       "blarg",
		TimeoutMillis: Int(120000),
	}

	_, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}
}

func TestCreateExectuableCredential_TimeoutTooHigh(t *testing.T) {
	ec := ExecutableConfig{
		Command:       "blarg",
		TimeoutMillis: Int(120001),
	}

	_, err := CreateExecutableCredential(context.Background(), &ec, nil)
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), timeoutRangeError().Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func areSlicesEquivalent(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

OUTER:
	for _, aa := range a {
		for _, bb := range b {
			if aa == bb {
				continue OUTER
			}
		}
		return false
	}
	return true
}

func TestMinimalExecutableCredentialGetEnvironment(t *testing.T) {
	config := Config{
		Audience:         "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		CredentialSource: CredentialSource{
			Executable: &ExecutableConfig{
				Command: "blarg",
			},
		},
	}

	ecs, err := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}

	oldBaseEnv := baseEnv
	defer func() { baseEnv = oldBaseEnv }()
	baseEnv = func() []string {
		return []string{"A=B"}
	}

	expectedEnvironment := []string{
		"A=B",
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE=%v", config.Audience),
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE=%v", config.SubjectTokenType),
		"GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE=0",
	}

	if got, want := ecs.getEnvironment(), expectedEnvironment; !areSlicesEquivalent(got, want) {
		t.Errorf("Incorrect environment received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestExectuableCredentialGetEnvironmentMalformedImpersonationUrl(t *testing.T) {
	config := Config{
		Audience:                       "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc",
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@project.iam.gserviceaccount.com:generateAccessToken",
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		CredentialSource: CredentialSource{
			Executable: &ExecutableConfig{
				Command:    "blarg",
				OutputFile: "/path/to/generated/cached/credentials",
			},
		},
	}

	ecs, err := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}

	oldBaseEnv := baseEnv
	defer func() { baseEnv = oldBaseEnv }()
	baseEnv = func() []string {
		return []string{"A=B"}
	}

	expectedEnvironment := []string{
		"A=B",
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE=%v", config.Audience),
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE=%v", config.SubjectTokenType),
		"GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL=test@project.iam.gserviceaccount.com",
		"GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE=0",
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE=%v", config.CredentialSource.Executable.OutputFile),
	}

	if got, want := ecs.getEnvironment(), expectedEnvironment; !areSlicesEquivalent(got, want) {
		t.Errorf("Incorrect environment received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestExectuableCredentialGetEnvironment(t *testing.T) {
	config := Config{
		Audience:                       "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc",
		ServiceAccountImpersonationURL: "test@project.iam.gserviceaccount.com",
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		CredentialSource: CredentialSource{
			Executable: &ExecutableConfig{
				Command:    "blarg",
				OutputFile: "/path/to/generated/cached/credentials",
			},
		},
	}

	ecs, err := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)
	if err != nil {
		t.Fatalf("creation failed %v", err)
	}

	oldBaseEnv := baseEnv
	defer func() { baseEnv = oldBaseEnv }()
	baseEnv = func() []string {
		return []string{"A=B"}
	}

	expectedEnvironment := []string{
		"A=B",
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE=%v", config.Audience),
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE=%v", config.SubjectTokenType),
		"GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE=0",
		fmt.Sprintf("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE=%v", config.CredentialSource.Executable.OutputFile),
	}

	if got, want := ecs.getEnvironment(), expectedEnvironment; !areSlicesEquivalent(got, want) {
		t.Errorf("Incorrect environment received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveExecutableSubjectTokenWithoutEnvironmentVariablesSet(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv := getenv
	defer func() { getenv = oldGetenv }()
	getenv = setEnvironment(map[string]string{})

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), executablesDisallowedError().Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveExecutableSubjectTokenInvalidFormat(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return []byte("tokentokentoken"), nil
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), jsonParsingError(executableSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenMissingVersion(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(true),
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "version").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenMissingSuccess(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Version: 1,
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "success").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenUnsuccessfulResponseWithFields(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(false),
			Version: 1,
			Code:    "404",
			Message: "Token Not Found",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), userDefinedError(executableSource, "404", "Token Not Found").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenUnsuccessfulResponseWithCode(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(false),
			Version: 1,
			Code:    "404",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(executableSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenUnsuccessfulResponseWithMessage(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(false),
			Version: 1,
			Message: "Token Not Found",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(executableSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenUnsuccessfulResponseWithoutFields(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(false),
			Version: 1,
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(executableSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenNewerVersion(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success: Bool(true),
			Version: 2,
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), unsupportedVersionError(executableSource, 2).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenMissingExpiration(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:   Bool(true),
			Version:   1,
			TokenType: "urn:ietf:params:oauth:token-type:jwt",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "expiration_time").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenTokenTypeMissing(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix(),
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "token_type").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenInvalidTokenType(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix(),
			TokenType:      "urn:ietf:params:oauth:token-type:invalid",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), tokenTypeError(executableSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenExpired(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() - 1,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), tokenExpiredError().Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenJwt(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
			IdToken:        "tokentokentoken",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveExecutableSubjectTokenJwtMissingIdToken(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "id_token").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveExecutableSubjectTokenIdToken(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:id_token",
			IdToken:        "tokentokentoken",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveExecutableSubjectTokenSaml(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:saml2",
			SamlResponse:   "tokentokentoken",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveExecutableSubjectTokenSamlMissingResponse(t *testing.T) {
	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:saml2",
		})
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(executableSource, "saml_response").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}

func TestRetrieveOutputFileSubjectTokenInvalidFormat(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if _, err = outputFile.Write([]byte("tokentokentoken")); err != nil {
		t.Fatalf("error writing to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), jsonParsingError(outputFileSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenMissingVersion(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(true),
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "version").Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenMissingSuccess(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Version: 1,
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "success").Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenUnsuccessfulResponseWithFields(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(false),
		Version: 1,
		Code:    "404",
		Message: "Token Not Found",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), userDefinedError(outputFileSource, "404", "Token Not Found").Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenUnsuccessfulResponseWithCode(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(false),
		Version: 1,
		Code:    "404",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(outputFileSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenUnsuccessfulResponseWithMessage(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(false),
		Version: 1,
		Message: "Token Not Found",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(outputFileSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenUnsuccessfulResponseWithoutFields(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(false),
		Version: 1,
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), malformedFailureError(outputFileSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenNewerVersion(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success: Bool(true),
		Version: 2,
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), unsupportedVersionError(outputFileSource, 2).Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenJwt(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() + 3600,
		TokenType:      "urn:ietf:params:oauth:token-type:jwt",
		IdToken:        "tokentokentoken",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenJwtMissingIdToken(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() + 3600,
		TokenType:      "urn:ietf:params:oauth:token-type:jwt",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "id_token").Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenIdToken(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() + 3600,
		TokenType:      "urn:ietf:params:oauth:token-type:id_token",
		IdToken:        "tokentokentoken",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenSaml(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() + 3600,
		TokenType:      "urn:ietf:params:oauth:token-type:saml2",
		SamlResponse:   "tokentokentoken",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenSamlMissingResponse(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() + 3600,
		TokenType:      "urn:ietf:params:oauth:token-type:saml2",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "saml_response").Error(); got != want {
		t.Errorf("Incorrect error received.\nExpected: %s\nRecieved: %s", want, got)
	}
}

func TestRetrieveOutputFileSubjectTokenMissingExpiration(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:   Bool(true),
		Version:   1,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "expiration_time").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveOutputFileSubjectTokenTokenTypeMissing(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix(),
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), missingFieldError(outputFileSource, "token_type").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveOutputFileSubjectTokenInvalidTokenType(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		t.Fatalf("Executable called when it should not have been")
		return []byte{}, nil
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix(),
		TokenType:      "urn:ietf:params:oauth:token-type:invalid",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("Expected error but found none")
	}
	if got, want := err.Error(), tokenTypeError(outputFileSource).Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}
}

func TestRetrieveOutputFileSubjectTokenExpired(t *testing.T) {
	outputFile, err := ioutil.TempFile("testdata", "result.*.json")
	if err != nil {
		t.Fatalf("Tempfile failed: %v", err)
	}
	defer os.Remove(outputFile.Name())

	cs := CredentialSource{
		Executable: &ExecutableConfig{
			Command:       "blarg",
			TimeoutMillis: Int(5000),
			OutputFile:    outputFile.Name(),
		},
	}

	tfc := testFileConfig
	tfc.CredentialSource = cs

	oldGetenv, oldNow, oldRunCommand := getenv, now, runCommand
	defer func() {
		getenv, now, runCommand = oldGetenv, oldNow, oldRunCommand
	}()

	getenv = setEnvironment(map[string]string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
	now = setTime(defaultTime)
	deadline, deadlineSet := now(), false
	runCommand = func(ctx context.Context, command string, env []string) ([]byte, error) {
		deadline, deadlineSet = ctx.Deadline()
		return json.Marshal(executableResponse{
			Success:        Bool(true),
			Version:        1,
			ExpirationTime: now().Unix() + 3600,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
			IdToken:        "tokentokentoken",
		})
	}

	if err = json.NewEncoder(outputFile).Encode(executableResponse{
		Success:        Bool(true),
		Version:        1,
		ExpirationTime: now().Unix() - 1,
		TokenType:      "urn:ietf:params:oauth:token-type:jwt",
	}); err != nil {
		t.Fatalf("Error encoding to file: %v", err)
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}

	if got, want := out, "tokentokentoken"; got != want {
		t.Errorf("Incorrect token received.\nExpected: %s\nRecieved: %s", want, got)
	}
}
