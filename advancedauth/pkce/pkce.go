package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"github.com/cloudentity/oauth2"
)

type PKCE struct {
	Method    Method
	Challenge string
	Verifier  string
}

type Method string

const (
	S256 Method = "S256"
	S384 Method = "S384"
	S512 Method = "S512"
	// not recommended, use S256
	Plain Method = "plain"
)

// https://www.rfc-editor.org/rfc/rfc7636#section-4.1
const verifierDict = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

func New() (PKCE, error) {
	return NewWithMethodVerifierLength(S256, 64)
}

func NewWithMethodVerifierLength(method Method, verifierLength int) (PKCE, error) {
	var (
		verifier  string
		challenge string
		err       error
	)
	if verifierLength < 43 || verifierLength > 128 {
		// https://www.rfc-editor.org/rfc/rfc7636#section-4.1
		return PKCE{}, errors.New("verifier has to be between 43 and 128 chars long")
	}

	if verifier, err = randomVerifer(verifierLength); err != nil {
		return PKCE{}, err
	}
	if challenge, err = calculateChallenge(verifier, method); err != nil {
		return PKCE{}, err
	}

	return PKCE{
		Method:    method,
		Challenge: challenge,
		Verifier:  verifier,
	}, nil
}

func randomVerifer(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = verifierDict[b%byte(len(verifierDict))]
	}
	return string(bytes), nil
}

func calculateChallenge(verifier string, method Method) (string, error) {
	var (
		hasher hash.Hash
	)
	switch method {
	case Plain:
		return verifier, nil
	case S256:
		hasher = sha256.New()
	case S384:
		hasher = sha512.New384()
	case S512:
		hasher = sha512.New()
	}
	if hasher != nil {
		if _, err := hasher.Write([]byte(verifier)); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
	}
	return "", fmt.Errorf("invalid method %s", method)
}

func (p *PKCE) ChallengeOpt() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge", p.Challenge)
}

func (p *PKCE) MethodOpt() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", string(p.Method))
}

func (p *PKCE) VerifierOpt() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", p.Verifier)
}

func (p *PKCE) AuthCodeURLOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		p.ChallengeOpt(), p.MethodOpt(),
	}
}

func (p *PKCE) ExchangeOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		p.VerifierOpt(), p.MethodOpt(),
	}
}
