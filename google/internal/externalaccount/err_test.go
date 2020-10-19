package externalaccount

import "testing"

func TestError_Generator(t *testing.T) {
	e := Error{
		"42",
		"http:thisIsAPlaceholder",
		"The Answer!",
	}
	want := "got error code 42 from http:thisIsAPlaceholder: The Answer!"
	if got := e.Error(); got != want {
		t.Errorf("Got error message %q; want %q", got, want)
	}
}
