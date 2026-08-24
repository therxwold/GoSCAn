package httpjson

import (
	"encoding/json"
	"fmt"
	"io"
)

// MaxResponseSize is the largest successful JSON response accepted from a provider.
const MaxResponseSize int64 = 32 << 20

// Decode reads exactly one size-limited JSON value from r into destination.
func Decode(r io.Reader, destination any) error {
	return decode(r, destination, MaxResponseSize)
}

// decode implements Decode with a configurable limit for focused tests.
func decode(r io.Reader, destination any, limit int64) error {
	limited := &io.LimitedReader{R: r, N: limit + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(destination); err != nil {
		if limited.N <= 0 {
			return fmt.Errorf("JSON response exceeds %d bytes", limit)
		}
		return err
	}
	var trailing any
	err := decoder.Decode(&trailing)
	if limited.N <= 0 {
		return fmt.Errorf("JSON response exceeds %d bytes", limit)
	}
	if err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON response contains multiple values")
		}
		return err
	}
	return nil
}
