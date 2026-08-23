package reachability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/therxwold/GoSCAn/internal/model"
	"golang.org/x/vuln/scan"
)

// Evidence is symbol-level reachability evidence keyed by advisory ID.
type Evidence struct {
	Level      model.Reachability
	CallStacks [][]model.CallFrame
}

// Analyzer runs the official Go vulnerability analyzer over source and tests.
type Analyzer struct{}

// Analyze runs govulncheck over production and test packages below root.
func (Analyzer) Analyze(ctx context.Context, root string) (map[string]Evidence, error) {
	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, "-C", root, "-json", "-test", "./...")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			return nil, fmt.Errorf("govulncheck: %w: %s", err, stderr.String())
		}
	}
	return parse(bytes.NewReader(stdout.Bytes()))
}

// message models the finding subset of govulncheck's streaming JSON protocol.
type message struct {
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Module   string `json:"module"`
			Package  string `json:"package"`
			Function string `json:"function"`
			Position *struct {
				Filename string `json:"filename"`
				Line     int    `json:"line"`
			} `json:"position"`
		} `json:"trace"`
	} `json:"finding"`
}

// parse reduces govulncheck messages to strongest evidence grouped by advisory ID.
func parse(r io.Reader) (map[string]Evidence, error) {
	out := map[string]Evidence{}
	dec := json.NewDecoder(r)
	for {
		var msg message
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode govulncheck output: %w", err)
		}
		if msg.Finding == nil || msg.Finding.OSV == "" || len(msg.Finding.Trace) == 0 {
			continue
		}
		trace := msg.Finding.Trace
		first := trace[0]
		level := model.ReachabilityModule
		if first.Package != "" {
			level = model.ReachabilityPackage
		}
		if first.Function != "" {
			level = model.ReachabilityCalled
		}
		evidence := out[msg.Finding.OSV]
		if reachabilityRank(level) > reachabilityRank(evidence.Level) {
			evidence.Level = level
		}
		if level == model.ReachabilityCalled {
			// govulncheck emits sink-to-source traces. Reports are easier to read in
			// execution order, so reverse the frames while converting them.
			stack := make([]model.CallFrame, 0, len(trace))
			for i := len(trace) - 1; i >= 0; i-- {
				frame := trace[i]
				converted := model.CallFrame{Module: frame.Module, Package: frame.Package, Function: frame.Function}
				if frame.Position != nil {
					converted.File = frame.Position.Filename
					converted.Line = frame.Position.Line
				}
				stack = append(stack, converted)
			}
			evidence.CallStacks = append(evidence.CallStacks, stack)
		}
		out[msg.Finding.OSV] = evidence
	}
	return out, nil
}

// reachabilityRank orders evidence levels from selected module to called symbol.
func reachabilityRank(level model.Reachability) int {
	switch level {
	case model.ReachabilityCalled:
		return 4
	case model.ReachabilitySymbol:
		return 3
	case model.ReachabilityPackage:
		return 2
	case model.ReachabilityModule:
		return 1
	default:
		return 0
	}
}
