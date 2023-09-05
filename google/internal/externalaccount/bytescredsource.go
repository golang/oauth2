// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE bytes.

package externalaccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type bytesCredentialSource struct {
	Bytes  []byte
	Format format
}

func (cs bytesCredentialSource) subjectToken() (string, error) {
	tokenBytes := bytes.TrimSpace(cs.Bytes)
	var err error
	switch cs.Format.Type {
	case "json":
		jsonData := make(map[string]interface{})
		err = json.Unmarshal(tokenBytes, &jsonData)
		if err != nil {
			return "", fmt.Errorf("oauth2/google: failed to unmarshal subject token bytes: %v", err)
		}
		val, ok := jsonData[cs.Format.SubjectTokenFieldName]
		if !ok {
			return "", errors.New("oauth2/google: provided subject_token_field_name not found in credentials")
		}
		token, ok := val.(string)
		if !ok {
			return "", errors.New("oauth2/google: improperly formatted subject token")
		}
		return token, nil
	case "text":
		return string(tokenBytes), nil
	case "":
		return string(tokenBytes), nil
	default:
		return "", errors.New("oauth2/google: invalid credential_source bytes format type")
	}
}
