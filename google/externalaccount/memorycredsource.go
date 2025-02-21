// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package externalaccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type memoryCredentialSource struct {
	Token  []byte
	Format Format
}

func (cs memoryCredentialSource) credentialSourceType() string {
	return "memory"
}

func (cs memoryCredentialSource) subjectToken() (string, error) {
	tokenBytes := bytes.TrimSpace(cs.Token)
	switch cs.Format.Type {
	case "json":
		jsonData := make(map[string]interface{})
		err := json.Unmarshal(tokenBytes, &jsonData)
		if err != nil {
			return "", fmt.Errorf("oauth2/google/externalaccount: failed to unmarshal subject token memory: %v", err)
		}
		val, ok := jsonData[cs.Format.SubjectTokenFieldName]
		if !ok {
			return "", errors.New("oauth2/google/externalaccount: provided subject_token_field_name not found in credentials")
		}
		token, ok := val.(string)
		if !ok {
			return "", errors.New("oauth2/google/externalaccount: improperly formatted subject token")
		}
		return token, nil
	case "text":
		return string(tokenBytes), nil
	case "":
		return string(tokenBytes), nil
	default:
		return "", errors.New("oauth2/google/externalaccount: invalid credential_source memory format type")
	}
}
