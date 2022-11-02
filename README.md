# OAuth2 for Go - extended with advanced authentication

This repo is a drop-in replacement of `golang.org/x/oauth2`

It extends the original library with additional authentication methods:

- private_key_jwt
- tls_client_auth
- self_signed_tls_client_auth

Additionally, it also adds utility methods for easy use of PKCE.

## Installation

When using go modules you can run:

`go mod edit -replace golang.org/x/oauth2 github.com/cloudentity/oauth2`

## Usage

When using any of the originally supported authentication methods, there's no need to change anything.
This library can be used as a drop-in replacement.

For new authentication methods see the examples below:

### Private Key JWT

#### Client credentials

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
)
```

```go
    cfg := clientcredentials.Config{
        ClientID: "your client id",
        AuthStyle: oauth2.AuthStylePrivateKeyJWT,
        PrivateKeyAuth: advancedauth.PrivateKeyAuth{
    		Key:         "your PEM encoded private key",
    		Algorithm:   advancedauth.RS256,
    		Exp:         30 * time.Second,
        },
    }

    token, err := cfg.Token(context.Background())
```

#### Authorization code

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
)
```

```go

    cfg := oauth2.Config{
        ClientID: "your client id",
        Endpoint: oauth2.Endpoint{
            AuthStyle: oauth2.AuthStylePrivateKeyJWT,
        },
        PrivateKeyAuth: advancedauth.PrivateKeyAuth{
    		Key:         "your PEM encoded private key",
    		Algorithm:   advancedauth.RS256,
    		Exp:         30 * time.Second,
        },
        Scopes: []string{"scope1", "scope2"},
    },

    token, err := cfg.Exchange(context.Background(), "your authorization code")
```

### TLS Auth

Both `tls_client_auth` and `self_signed_tls_client_auth` are handled with `TLSAuth`

#### Client credentials

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
	"github.com/cloudentity/oauth2/clientcredentials"
)
```

```go
    cfg := clientcredentials.Config{
        ClientID: "your client id",
        AuthStyle: oauth2.AuthStyleTLS,
    	TLSAuth: advancedauth.TLSAuth{
    		Key:   "your certificate PEM encoded private key",
    		Certificate:   "your PEM encoded TLS certificate",
    	},
    }

    token, err := cfg.Token(context.Background())
```

#### Authorization code

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth"
)
```

```go

    cfg := oauth2.Config{
        ClientID: "your client id",
        Endpoint: oauth2.Endpoint{
            AuthStyle: oauth2.AuthStyleTLS,
        },
    	TLSAuth: advancedauth.TLSAuth{
    		Key:   "your certificate PEM encoded private key",
    		Certificate:   "your PEM encoded TLS certificate",
    	},
        Scopes: []string{"scope1", "scope2"},
    },

    token, err := cfg.Exchange(context.Background(), "your authorization code")
```

### PKCE

```go
import (
	"context"
	"time"

	"github.com/cloudentity/oauth2"
	"github.com/cloudentity/oauth2/advancedauth/pkce"
)
```

Create `PKCE` with

```go
    p, err := pkce.New()
```

or, if you want to specify the code challenge method and verifier length

```go
    p, err := pkce.NewWithMethodVerifierLength(pkce.512, 84)
```

#### AuthCodeURL

`PKCE` exposes few utility methods to ease creating `AuthCodeURL`

You can use utility methods returning needed `AuthCodeOption`'s

```
    url = conf.AuthCodeURL("state", p.AuthCodeURLOpts()...)
```

or, individual methods

```
    url := conf.AuthCodeURL("state", p.ChallengeOpt(), p.MethodOpt())
```

#### Exchange

`PKCE` also exposes similar methods for `Exchange`

```go
    tok, err := conf.Exchange(context.Background(), "exchange-code", p.ExchangeOpts()...)
```

or, with individual methods

```go
    tok, err := conf.Exchange(context.Background(), "exchange-code", p.VerifierOpt(), p.MethodOpt())
```

## Implementation

This fork tries to limit changes to the original codebase to the minimum.
All the new major changes are implemented in the `advancedauth` package.
