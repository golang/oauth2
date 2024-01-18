// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

type programmaticRefreshCredentialSource struct {
	SubjectTokenSupplier func() (string, error)
}

func (cs programmaticRefreshCredentialSource) credentialSourceType() string {
	return "programmatic"
}

func (cs programmaticRefreshCredentialSource) subjectToken() (string, error) {
	return cs.SubjectTokenSupplier()
}
