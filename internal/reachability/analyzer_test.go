package reachability

import (
	"slices"
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

// TestCommandArgsAddsDatabase verifies alternate database forwarding to govulncheck.
func TestCommandArgsAddsDatabase(t *testing.T) {
	got := commandArgs("/src", "file:///cache/vulndb")
	want := []string{"-C", "/src", "-json", "-test", "-db", "file:///cache/vulndb", "./..."}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCommandArgsOmitsEmptyDatabase verifies the public default remains available.
func TestCommandArgsOmitsEmptyDatabase(t *testing.T) {
	got := commandArgs(".", "")
	want := []string{"-C", ".", "-json", "-test", "./..."}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestParseKeepsStrongestEvidenceAndReversesTrace verifies govulncheck reduction.
func TestParseKeepsStrongestEvidenceAndReversesTrace(t *testing.T) {
	input := strings.NewReader(`
{"finding":{"osv":"GO-1","trace":[{"module":"m"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","package":"m/p"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","package":"m/p","function":"Vulnerable"},{"module":"app","package":"app","function":"main","position":{"filename":"main.go","line":10}}]}}
`)
	got, err := parse(input)
	if err != nil {
		t.Fatal(err)
	}
	evidence := got["GO-1"]
	if evidence.Level != model.ReachabilityCalled || len(evidence.CallStacks) != 1 {
		t.Fatalf("evidence=%+v", evidence)
	}
	stack := evidence.CallStacks[0]
	if stack[0].Function != "main" || stack[0].File != "main.go" || stack[1].Function != "Vulnerable" {
		t.Fatalf("stack=%+v", stack)
	}
}
