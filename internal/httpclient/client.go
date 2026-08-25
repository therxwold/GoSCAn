package httpclient

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const (
	// defaultMaxAttempts bounds one logical provider request, including its
	// initial attempt.
	defaultMaxAttempts = 3
	// defaultBaseDelay is the upper jitter bound after the first failed attempt.
	defaultBaseDelay = 250 * time.Millisecond
	// defaultMaxDelay prevents a provider from forcing excessive retry sleeps.
	defaultMaxDelay = 2 * time.Second
	// retryDrainLimit bounds response data discarded before a retry.
	retryDrainLimit = 64 << 10
)

// sleepFunc waits between attempts while observing request cancellation.
type sleepFunc func(context.Context, time.Duration) error

// jitterFunc selects a full-jitter delay below the supplied upper bound.
type jitterFunc func(time.Duration) time.Duration

// retryTransport adds bounded retries to an underlying HTTP transport.
type retryTransport struct {
	base        http.RoundTripper
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	sleep       sleepFunc
	jitter      jitterFunc
}

// New returns an HTTP client with a total request timeout and bounded retries
// for transient transport failures and retryable HTTP responses.
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &retryTransport{
			base:        http.DefaultTransport,
			maxAttempts: defaultMaxAttempts,
			baseDelay:   defaultBaseDelay,
			maxDelay:    defaultMaxDelay,
			sleep:       sleepContext,
			jitter:      fullJitter,
		},
	}
}

// RoundTrip executes req and retries only when the request body can be replayed
// safely and the response or transport error is classified as transient.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	maxAttempts := t.maxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptRequest, err := requestAttempt(req, attempt)
		if err != nil {
			return nil, err
		}
		response, requestErr := base.RoundTrip(attemptRequest)
		if attempt == maxAttempts || !retryable(req.Context(), response, requestErr) || !replayable(req) {
			return response, requestErr
		}

		discardResponse(response)
		delay := t.delay(response, attempt)
		logRetry(req, response, requestErr, attempt, maxAttempts, delay)
		sleep := t.sleep
		if sleep == nil {
			sleep = sleepContext
		}
		if err := sleep(req.Context(), delay); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("HTTP retry loop ended unexpectedly")
}

// requestAttempt returns the original request first and reconstructs its body
// for every later attempt.
func requestAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 1 {
		return req, nil
	}
	clone := req.Clone(req.Context())
	if req.Body == nil {
		return clone, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// replayable reports whether a request can be issued again without losing or
// changing its body.
func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// retryable classifies transient transport failures and HTTP status codes.
func retryable(ctx context.Context, response *http.Response, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		var networkError net.Error
		networkRetry := errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
		return networkRetry || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	}
	if response == nil {
		return false
	}
	switch response.StatusCode {
	case http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// delay returns a capped Retry-After delay when present, otherwise exponential
// full jitter for the completed attempt number.
func (t *retryTransport) delay(response *http.Response, attempt int) time.Duration {
	maximum := t.maxDelay
	if maximum <= 0 {
		maximum = defaultMaxDelay
	}
	if delay, ok := retryAfter(response, time.Now()); ok {
		return min(delay, maximum)
	}
	base := t.baseDelay
	if base <= 0 {
		base = defaultBaseDelay
	}
	upper := base
	for i := 1; i < attempt && upper < maximum; i++ {
		upper = min(upper*2, maximum)
	}
	jitter := t.jitter
	if jitter == nil {
		jitter = fullJitter
	}
	return jitter(upper)
}

// retryAfter parses both delta-seconds and HTTP-date forms of Retry-After.
func retryAfter(response *http.Response, now time.Time) (time.Duration, bool) {
	if response == nil {
		return 0, false
	}
	value := strings.TrimSpace(response.Header.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0, false
	}
	return when.Sub(now), true
}

// discardResponse closes a failed attempt and drains a bounded prefix so small
// provider responses can reuse their underlying connection.
func discardResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, retryDrainLimit))
	_ = response.Body.Close()
}

// logRetry records safe request metadata without leaking paths, queries,
// credentials, advisory identifiers, or module names.
func logRetry(req *http.Request, response *http.Response, err error, attempt, maxAttempts int, delay time.Duration) {
	event := zerolog.Ctx(req.Context()).Warn().
		Str("method", req.Method).
		Str("host", req.URL.Hostname()).
		Int("attempt", attempt).
		Int("max_attempts", maxAttempts).
		Dur("retry_in", delay)
	if response != nil {
		event = event.Int("status", response.StatusCode)
	}
	if err != nil {
		event = event.Err(err)
	}
	event.Msg("retrying provider request")
}

// sleepContext waits for delay or returns as soon as ctx is canceled.
func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fullJitter selects a random duration from zero through upper.
func fullJitter(upper time.Duration) time.Duration {
	if upper <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(upper) + 1))
}
