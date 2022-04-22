// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"encoding/json"
	"fmt"
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
		TimeoutMillis: 50000,
	}

	ecs := CreateExecutableCredential(context.Background(), &ec, nil)
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

	ecs := CreateExecutableCredential(context.Background(), &ec, nil)
	if ecs.Command != "blarg" {
		t.Errorf("ecs.Command got %v but want %v", ecs.Command, "blarg")
	}
	if ecs.Timeout != defaultTimeout {
		t.Errorf("ecs.Timeout got %v but want %v", ecs.Timeout, 30000*time.Millisecond)
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

	ecs := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)

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

	ecs := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)

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

	ecs := CreateExecutableCredential(context.Background(), config.CredentialSource.Executable, &config)

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
			TimeoutMillis: 5000,
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
			TimeoutMillis: 5000,
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
	if got, want := err.Error(), jsonParsingError().Error(); got != want {
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
			TimeoutMillis: 5000,
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
	if got, want := err.Error(), missingFieldError("version").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(1),
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
	if got, want := err.Error(), missingFieldError("success").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(1),
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
	if got, want := err.Error(), userDefinedError("404", "Token Not Found").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(1),
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
	if got, want := err.Error(), malformedFailureError().Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(1),
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
	if got, want := err.Error(), malformedFailureError().Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(1),
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
	if got, want := err.Error(), malformedFailureError().Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version: Int(2),
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
	if got, want := err.Error(), unsupportedVersionError(2).Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version:   Int(1),
			TokenType: String("urn:ietf:params:oauth:token-type:jwt"),
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
	if got, want := err.Error(), missingFieldError("expiration_time").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix()),
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
	if got, want := err.Error(), missingFieldError("token_type").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix()),
			TokenType:      String("urn:ietf:params:oauth:token-type:invalid"),
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
	if got, want := err.Error(), tokenTypeError().Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() - 1),
			TokenType:      String("urn:ietf:params:oauth:token-type:jwt"),
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() + 3600),
			TokenType:      String("urn:ietf:params:oauth:token-type:jwt"),
			IdToken:        String("tokentokentoken"),
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() + 3600),
			TokenType:      String("urn:ietf:params:oauth:token-type:jwt"),
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
	if got, want := err.Error(), missingFieldError("id_token").Error(); got != want {
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() + 3600),
			TokenType:      String("urn:ietf:params:oauth:token-type:id_token"),
			IdToken:        String("tokentokentoken"),
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() + 3600),
			TokenType:      String("urn:ietf:params:oauth:token-type:saml2"),
			SamlResponse:   String("tokentokentoken"),
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
			TimeoutMillis: 5000,
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
			Version:        Int(1),
			ExpirationTime: Int64(now().Unix() + 3600),
			TokenType:      String("urn:ietf:params:oauth:token-type:saml2"),
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
	if got, want := err.Error(), missingFieldError("saml_response").Error(); got != want {
		t.Errorf("Incorrect error received.\nReceived: %s\nExpected: %s", got, want)
	}

	if !deadlineSet {
		t.Errorf("Command run without a deadline")
	} else if deadline != now().Add(5*time.Second) {
		t.Errorf("Command run with incorrect deadline")
	}
}
