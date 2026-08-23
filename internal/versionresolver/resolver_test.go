package versionresolver

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// runner returns command output keyed by invocation.
type runner map[string][]byte

// Run implements command.Runner for resolver tests.
func (r runner) Run(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	v, ok := r[name+" "+strings.Join(args, " ")]
	if !ok {
		return nil, fmt.Errorf("unexpected")
	}
	return v, nil
}

// TestLatest verifies @latest resolution and Go-version normalization.
func TestLatest(t *testing.T) {
	r := Resolver{Runner: runner{"go list -m -json example.com/a@latest": []byte(`{"Version":"v1.9.0"}`)}}
	got, err := r.Latest(context.Background(), ".", "example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1.9.0" {
		t.Fatalf("got %q", got)
	}
}
