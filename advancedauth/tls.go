package advancedauth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/cloudentity/oauth2"
)

type TLSAuth struct {
	// Key is the private key for client TLS certificate
	Key string
	// Certificate is the client TLS certificate
	Certificate string
}

func extendContextWithTLSClient(ctx context.Context, c Config) (context.Context, error) {
	var (
		hc   *http.Client
		ok   bool
		cert tls.Certificate
		err  error
		tr   *http.Transport
	)
	if ctx == nil {
		ctx = context.Background()
	}

	if ctx.Value(oauth2.HTTPClient) == nil {
		hc = http.DefaultClient
	} else if hc, ok = ctx.Value(oauth2.HTTPClient).(*http.Client); !ok {
		return nil, errors.New("client of type *http.Client required in context")
	}

	if cert, err = tls.X509KeyPair([]byte(c.TLSAuth.Certificate), []byte(c.TLSAuth.Key)); err != nil {
		return nil, err
	}

	if hc.Transport == nil {
		tr = &http.Transport{}
	} else if tr, ok = hc.Transport.(*http.Transport); !ok {
		return nil, errors.New("transport of type *http.Transport required in context")
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	hc.Transport = tr

	return context.WithValue(ctx, oauth2.HTTPClient, hc), nil

}
