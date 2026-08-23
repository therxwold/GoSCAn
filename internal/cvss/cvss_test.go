package cvss

import "testing"

// TestScoreV3 verifies CVSS 3.1 parsing and scoring.
func TestScoreV3(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", 8.3},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 6.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, tt := range tests {
		got, _, err := ScoreV3(tt.vector)
		if err != nil {
			t.Fatalf("%s: %v", tt.vector, err)
		}
		if got != tt.want {
			t.Errorf("%s = %.1f want %.1f", tt.vector, got, tt.want)
		}
	}
}

// TestScoreCVSS2 verifies CVSS 2.0 parsing and scoring.
func TestScoreCVSS2(t *testing.T) {
	got, version, err := Score("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if err != nil {
		t.Fatal(err)
	}
	if version != "2.0" || got != 7.5 {
		t.Fatalf("score=%.1f version=%q", got, version)
	}
}

// TestScoreCVSS30 verifies CVSS 3.0 parsing and scoring.
func TestScoreCVSS30(t *testing.T) {
	got, version, err := Score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	if version != "3.0" || got != 9.8 {
		t.Fatalf("score=%.1f version=%q", got, version)
	}
}

// TestScoreCVSS4 verifies CVSS 4.0 parsing and scoring.
func TestScoreCVSS4(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	got, version, err := Score(vector)
	if err != nil {
		t.Fatal(err)
	}
	if version != "4.0" || got != 9.3 {
		t.Fatalf("score=%.1f version=%q", got, version)
	}
}
