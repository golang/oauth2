// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRetrieveSubjectToken_ProgrammaticAuth(t *testing.T) {
	tfc := testConfig

	tfc.SubjectTokenSupplier = func() (string, error) {
		return "subjectToken", nil
	}

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	out, err := base.subjectToken()
	if err != nil {
		t.Fatalf("retrieveSubjectToken() failed: %v", err)
	}

	if got, want := out, "subjectToken"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = \n%q\n want \n%q", got, want)
	}
}

func TestRetrieveSubjectToken_ProgrammaticAuthFails(t *testing.T) {
	tfc := testConfig

	tfc.SubjectTokenSupplier = func() (string, error) {
		return "", errors.New("test error")
	}

	oldNow := now
	defer func() {
		now = oldNow
	}()
	now = setTime(defaultTime)

	base, err := tfc.parse(context.Background())
	if err != nil {
		t.Fatalf("parse() failed %v", err)
	}

	_, err = base.subjectToken()
	if err == nil {
		t.Fatalf("subjectToken() should have failed")
	}
	if got, want := err.Error(), "test error"; !reflect.DeepEqual(got, want) {
		t.Errorf("subjectToken = %q, want %q", got, want)
	}
}
