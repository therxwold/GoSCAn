package cvss

import (
	"fmt"
	"strconv"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Score parses a CVSS vector and returns its score and CVSS version.
// CVSS 2.0, 3.0, 3.1, and 4.0 are supported.
func Score(vector string) (float64, string, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, "", fmt.Errorf("parse CVSS 4.0: %w", err)
		}
		return v.Score(), "4.0", nil
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, "", fmt.Errorf("parse CVSS 3.1: %w", err)
		}
		return v.BaseScore(), "3.1", nil
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, "", fmt.Errorf("parse CVSS 3.0: %w", err)
		}
		return v.BaseScore(), "3.0", nil
	default:
		vector = strings.TrimPrefix(vector, "CVSS:2.0/")
		v, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, "", fmt.Errorf("parse CVSS 2.0: %w", err)
		}
		return v.BaseScore(), "2.0", nil
	}
}

// ScoreV3 parses a CVSS v3.0/v3.1 vector and returns its base score.
func ScoreV3(vector string) (float64, string, error) {
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, "", fmt.Errorf("not a CVSS v3 vector")
	}
	return Score(vector)
}

// Severity converts a CVSS base score into its qualitative severity band.
func Severity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// ParseNumeric parses a numeric CVSS score and reports whether parsing succeeded.
func ParseNumeric(score string) (float64, bool) {
	v, err := strconv.ParseFloat(score, 64)
	return v, err == nil
}
