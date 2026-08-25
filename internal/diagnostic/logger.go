package diagnostic

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// New constructs a Zerolog logger for diagnostic events written to output.
// The disabled level discards all events, while text and json select the wire
// format without changing the command's report output.
func New(output io.Writer, levelName, formatName string) (zerolog.Logger, error) {
	levelName = strings.ToLower(strings.TrimSpace(levelName))
	formatName = strings.ToLower(strings.TrimSpace(formatName))
	if formatName != "text" && formatName != "json" {
		return zerolog.Logger{}, fmt.Errorf("invalid log format %q: expected text or json", formatName)
	}
	if levelName == "disabled" {
		return zerolog.Nop(), nil
	}
	level, err := zerolog.ParseLevel(levelName)
	if err != nil || level < zerolog.TraceLevel || level > zerolog.ErrorLevel {
		return zerolog.Logger{}, fmt.Errorf("invalid log level %q: expected disabled, trace, debug, info, warn, or error", levelName)
	}

	var writer io.Writer = output
	if formatName == "text" {
		writer = zerolog.ConsoleWriter{Out: output, NoColor: true, TimeFormat: time.RFC3339}
	}
	logger := zerolog.New(writer).Level(level).With().Timestamp().Logger()
	return logger, nil
}

// WithLogger validates diagnostic options and attaches their logger to parent.
func WithLogger(parent context.Context, output io.Writer, levelName, formatName string) (context.Context, error) {
	logger, err := New(output, levelName, formatName)
	if err != nil {
		return nil, err
	}
	return logger.WithContext(parent), nil
}
