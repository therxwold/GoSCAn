package httpjson

import (
	"strings"
	"testing"
)

// TestDecodeAcceptsOneJSONValue verifies ordinary provider responses.
func TestDecodeAcceptsOneJSONValue(t *testing.T) {
	var value struct {
		OK bool `json:"ok"`
	}
	if err := Decode(strings.NewReader(`{"ok":true}`), &value); err != nil {
		t.Fatal(err)
	}
	if !value.OK {
		t.Fatal("decoded value was not populated")
	}
}

// TestDecodeRejectsMultipleValues verifies trailing JSON cannot be ignored.
func TestDecodeRejectsMultipleValues(t *testing.T) {
	var value any
	if err := Decode(strings.NewReader(`{} {}`), &value); err == nil {
		t.Fatal("expected multiple JSON values to fail")
	}
}

// TestDecodeRejectsOversizedResponse verifies the shared memory ceiling.
func TestDecodeRejectsOversizedResponse(t *testing.T) {
	var value string
	response := `"` + strings.Repeat("x", 32) + `"`
	if err := decode(strings.NewReader(response), &value, 16); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}
