package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/output"
	"github.com/therxwold/GoSCAn/internal/scanner"
)

// Version is the current GoSCAn version.
const Version string = "v0.1.0"

// Run starts GoSCAn and exits with the command result code.
func Run() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "-v", "--version", "version":
			fmt.Fprintf(stdout, "goscan %s\n", Version)
			return 0
		case "help", "-h", "--help":
			usage(stdout)
			return 0
		case "scan":
			return runScan(args[1:], stdout, stderr)
		}
	}

	// Bare goscan [flags] [path] behaves like `goscan scan`.
	return runScan(args, stdout, stderr)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("goscan scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatName := fs.String("format", "terminal", "output format: terminal, json, sarif")
	jsonAlias := fs.Bool("json", false, "alias for --format=json")
	failOn := fs.String("fail-on", "none", "exit 1 at or above severity: none, low, medium, high, critical")
	epssThreshold := fs.Float64("epss-threshold", -1, "exit 1 when EPSS probability is at least this value (0..1); -1 disables")
	noEPSS := fs.Bool("no-epss", false, "disable FIRST EPSS enrichment")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall scan timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "goscan scan accepts at most one path")
		return 2
	}

	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	if *jsonAlias {
		*formatName = "json"
	}

	format, err := output.ParseFormat(*formatName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sev, err := scanner.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *epssThreshold > 1 || (*epssThreshold < 0 && *epssThreshold != -1) {
		fmt.Fprintln(stderr, "--epss-threshold must be -1 or between 0 and 1")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	s := scanner.New()
	s.ToolVersion = strings.TrimPrefix(Version, "v")
	report, err := s.Scan(ctx, dir, scanner.Options{NoEPSS: *noEPSS})
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if err := output.Write(stdout, report, format); err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if scanner.Exceeds(report, sev, *epssThreshold) {
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `GoSCAn - Go dependency vulnerability scanner and remediation planner

Usage:
  goscan [scan] [flags] [path]
  goscan version
  goscan -v

Scan every selected direct, indirect, and transitive Go module using OSV,
enrich CVEs with EPSS, and recommend the first fixed version. Transitive fixes
include an explicit go.mod // indirect pin when Go MVS can select the fixed
version from the main module.

Examples:
  goscan
  goscan scan --fail-on=high
  goscan scan --format=json
  goscan scan --format=sarif > goscan.sarif`)
}
