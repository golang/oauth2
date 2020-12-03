package externalaccount

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

type fileCredentialSource struct {
	File string
}

func (cs fileCredentialSource) retrieveSubjectToken(c *Config) (string, error) {
	tokenFile, err := os.Open(cs.File)
	if err != nil {
		return "", fmt.Errorf("Failed to open credential file %s\n", cs.File)
	}
	tokenBytes, _ := ioutil.ReadAll(tokenFile)
	if string(tokenBytes[len(tokenBytes)-1]) == "\n" { //Deals with a possible trailing newline character
		tokenBytes = tokenBytes[0 : len(tokenBytes)-1]
	}
	var output string
	switch c.CredentialSource.Format.Type {
	case "json":
		jsonData := make(map[string]interface{})
		json.Unmarshal(tokenBytes, &jsonData)
		if val, ok := jsonData[c.CredentialSource.Format.SubjectTokenFieldName]; !ok {
			return "", errors.New("oauth2/google: provided subject_token_field_name not found in credentials")
		} else {
			if token, ok := val.(string); !ok {
				return "", errors.New("oauth2/google: improperly formatted subject token")
			} else {
				output = token
			}

		}
	case "text":
		output = string(tokenBytes)
	case "":
		output = string(tokenBytes)
	default:
		return "", errors.New("oauth2/google: invalid credential_source file format type")
	}

	return output, nil

}
