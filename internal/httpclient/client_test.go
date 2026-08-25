package httpclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/therxwold/GoSCAn/internal/diagnostic"
)

// roundTripFunc adapts a function into an HTTP transport for focused retry
// tests that do not use the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f with req.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// newResponse constructs a response with a closable empty body.
func newResponse(status int, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("retry response"))}
}

// testTransport constructs a deterministic retry transport with no real sleep.
func testTransport(base http.RoundTripper, delays *[]time.Duration) *retryTransport {
	return &retryTransport{
		base: base, maxAttempts: 3, baseDelay: 100 * time.Millisecond, maxDelay: 2 * time.Second,
		sleep: func(_ context.Context, delay time.Duration) error {
			*delays = append(*delays, delay)
			return nil
		},
		jitter: func(upper time.Duration) time.Duration { return upper },
	}
}

// TestRetryTransportHonorsRetryAfter verifies retryable statuses, attempt
// limits, and Retry-After handling.
func TestRetryTransportHonorsRetryAfter(t *testing.T) {
	calls := 0
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return newResponse(http.StatusServiceUnavailable, http.Header{"Retry-After": []string{"1"}}), nil
		}
		return newResponse(http.StatusOK, nil), nil
	})
	var delays []time.Duration
	transport := testTransport(base, &delays)
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.test/data", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if calls != 2 || len(delays) != 1 || delays[0] != time.Second || response.StatusCode != http.StatusOK {
		t.Fatalf("calls=%d delays=%v status=%d", calls, delays, response.StatusCode)
	}
}

// TestRetryTransportReplaysPOSTBody verifies the OSV batch payload remains
// identical across attempts.
func TestRetryTransportReplaysPOSTBody(t *testing.T) {
	var bodies []string
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(data))
		if len(bodies) == 1 {
			return newResponse(http.StatusBadGateway, nil), nil
		}
		return newResponse(http.StatusOK, nil), nil
	})
	var delays []time.Duration
	transport := testTransport(base, &delays)
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.example.test/query", bytes.NewBufferString(`{"module":"private.example/app"}`))
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("request bodies changed across retries: %q", bodies)
	}
}

// TestRetryTransportDoesNotRetryPermanentStatus verifies ordinary client errors
// return immediately.
func TestRetryTransportDoesNotRetryPermanentStatus(t *testing.T) {
	calls := 0
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		return newResponse(http.StatusUnauthorized, nil), nil
	})
	var delays []time.Duration
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.test/data", nil)
	response, err := testTransport(base, &delays).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if calls != 1 || len(delays) != 0 {
		t.Fatalf("permanent response was retried: calls=%d delays=%v", calls, delays)
	}
}

// TestRetryLogRedactsRequestDetails verifies diagnostics retain the provider
// host without exposing paths, queries, or request bodies.
func TestRetryLogRedactsRequestDetails(t *testing.T) {
	var logs bytes.Buffer
	logger, err := diagnostic.New(&logs, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	ctx := logger.WithContext(context.Background())
	calls := 0
	base := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return newResponse(http.StatusTooManyRequests, nil), nil
		}
		return newResponse(http.StatusOK, nil), nil
	})
	var delays []time.Duration
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example.test/private/CVE-2026-1234?token=secret", bytes.NewBufferString("private.example/module"))
	response, err := testTransport(base, &delays).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	output := logs.String()
	if !strings.Contains(output, `"host":"api.example.test"`) {
		t.Fatalf("retry log has no provider host: %s", output)
	}
	for _, secret := range []string{"CVE-2026-1234", "token=secret", "private.example/module"} {
		if strings.Contains(output, secret) {
			t.Fatalf("retry log leaked %q: %s", secret, output)
		}
	}
}
