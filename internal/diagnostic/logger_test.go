package diagnostic

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestNewWritesStructuredJSON verifies enabled diagnostics retain attributes in
// a machine-readable stderr format.
func TestNewWritesStructuredJSON(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "info", "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info().Str("provider", "osv").Int("attempt", 2).Msg("retry")
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode log event: %v: %s", err, output.String())
	}
	if event["level"] != "info" || event["message"] != "retry" || event["provider"] != "osv" || event["attempt"] != float64(2) {
		t.Fatalf("unexpected log event: %#v", event)
	}
}

// TestNewDisabledDiscardsDiagnostics verifies logging remains opt-in.
func TestNewDisabledDiscardsDiagnostics(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "disabled", "text")
	if err != nil {
		t.Fatal(err)
	}
	logger.Error().Msg("must not be written")
	if output.Len() != 0 {
		t.Fatalf("disabled logger wrote %q", output.String())
	}
}

// TestNewRejectsInvalidSettings verifies malformed logging configuration fails
// before a scan begins.
func TestNewRejectsInvalidSettings(t *testing.T) {
	for name, settings := range map[string][2]string{
		"level":  {"loud", "text"},
		"format": {"info", "xml"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(&bytes.Buffer{}, settings[0], settings[1]); err == nil {
				t.Fatal("expected invalid diagnostic setting to fail")
			}
		})
	}
}
