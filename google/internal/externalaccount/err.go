package externalaccount

import "fmt"

// Error for handling OAuth related error responses as stated in rfc6749#5.2.
type Error struct {
	Code        string
	URI         string
	Description string
}

func (err *Error) Error() string {
	return fmt.Sprintf("got error code %s from %s: %s", err.Code, err.URI, err.Description)
}
