package privatekeyjwt

import (
	"crypto/rsa"
	"net/url"
	"strings"
	"time"

	"github.com/cloudentity/oauth2/internal"
	"github.com/cloudentity/oauth2/jws"
	"github.com/google/uuid"
)

const PrivateKeyJWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type AssertionConfig struct {
	ClientID   string
	PrivateKey string
	TokenURL   string
}

func JWTAssertionVals(c AssertionConfig) (url.Values, error) {
	var (
		key       *rsa.PrivateKey
		err       error
		assertion string
		id        uuid.UUID
	)

	if id, err = uuid.NewUUID(); err != nil {
		return url.Values{}, err
	}

	jti := id.String()

	claims := &jws.ClaimSet{
		Iss: c.ClientID,
		Sub: c.ClientID,
		Aud: strings.TrimSuffix(c.TokenURL, "/token"),
		Jti: jti,
		Exp: time.Now().Add(30 * time.Second).Unix(), // TODO configurable?
	}

	header := &jws.Header{
		Algorithm: "RS256", // TODO configurable ??
		Typ:       "JWT",
		KeyID:     "", // TODO fetch from config?
	}

	if key, err = internal.ParseKey([]byte(c.PrivateKey)); err != nil {
		return url.Values{}, err
	}

	if assertion, err = jws.Encode(header, claims, key); err != nil {
		return url.Values{}, err
	}

	return url.Values{
		"client_assertion":      []string{assertion},
		"client_assertion_type": []string{PrivateKeyJWTAssertionType},
	}, nil
}
