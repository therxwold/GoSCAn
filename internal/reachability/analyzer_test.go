package reachability

import (
	"strings"
	"testing"

	"github.com/therxwold/GoSCAn/internal/model"
)

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
