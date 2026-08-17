package goversion

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "1.2.3", 0},
		{"v1.2.2", "v1.2.3", -1},
		{"v2.0.0", "v1.99.99", 1},
		{"v1.2.3-rc.1", "v1.2.3", -1},
		{"v1.2.3-rc.2", "v1.2.3-rc.10", -1},
		{"v1.2.3+incompatible", "v1.2.3", 0},
		{"v1.2", "v1.2.0", 0},
		{"0", "v0.0.0", -1},
		{"v0.0.0-20260101000000-aaaa", "v0.0.0-20260201000000-bbbb", -1},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q,%q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestNormalizeForGo(t *testing.T) {
	if got := NormalizeForGo("1.2.3"); got != "v1.2.3" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeForGo("v1.2.3"); got != "v1.2.3" {
		t.Fatalf("got %q", got)
	}
}
