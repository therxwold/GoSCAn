package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/therxwold/GoSCAn/internal/config"
	"github.com/therxwold/GoSCAn/internal/fixer"
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/nvd"
	"github.com/therxwold/GoSCAn/internal/output"
	"github.com/therxwold/GoSCAn/internal/scanner"
)

// Version is the current GoSCAn version.
const Version string = "v0.3.0"

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
		case "fix":
			return runFix(args[1:], stdout, stderr)
		}
	}

	// Bare goscan [flags] [path] behaves like `goscan scan`.
	return runScan(args, stdout, stderr)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	configPath, configExplicit, err := config.PathFromArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := config.Load(configPath, configExplicit)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}

	ignoreRules := copyIgnoreRules(cfg.Ignore.Rules)
	fs := flag.NewFlagSet("goscan scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.String("config", configPath, "configuration file (default config.yml when present)")
	formatName := fs.String("format", cfg.Output.Format, "output format: terminal, json, sarif")
	jsonAlias := fs.Bool("json", false, "alias for --format=json")
	failOn := fs.String("fail-on", cfg.Scan.FailOn, "exit 1 at or above severity: none, low, medium, high, critical")
	epssThreshold := fs.Float64("epss-threshold", cfg.Scan.EPSSThreshold, "exit 1 when EPSS probability is at least this value (0..1); -1 disables")
	githubEnabled := fs.Bool("github", cfg.GitHub.Enabled, "enable GitHub Advisory Database enrichment")
	nvdEnabled := fs.Bool("nvd", cfg.NVD.Enabled, "enable NVD enrichment")
	noGitHub := fs.Bool("no-github", false, "disable GitHub Advisory Database enrichment")
	noNVD := fs.Bool("no-nvd", false, "disable NVD enrichment")
	noEPSS := fs.Bool("no-epss", !cfg.EPSS.Enabled, "disable FIRST EPSS enrichment")
	showIgnored := fs.Bool("show-ignored", cfg.Ignore.Show, "show findings suppressed as false positives")
	showManifests := fs.Bool("show-manifests", cfg.Scan.ShowManifests, "show requirements declared by selected dependency manifests")
	fs.Func("ignore", "ignore advisory ID or module@ID; append =reason if wanted; repeatable", func(value string) error {
		return addIgnoreRule(ignoreRules, value)
	})
	githubToken := fs.String("github-token", "", "GitHub token override; environment variables are safer")
	nvdAPIKey := fs.String("nvd-api-key", "", "NVD API key override; environment variables are safer")
	timeout := fs.Duration("timeout", cfg.Scan.Timeout, "overall scan timeout")
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
	if *noGitHub {
		*githubEnabled = false
	}
	if *noNVD {
		*nvdEnabled = false
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

	githubAuth := cfg.GitHub.Token
	if *githubToken != "" {
		githubAuth = *githubToken
	}
	nvdAuth := cfg.NVD.APIKey
	if *nvdAPIKey != "" {
		nvdAuth = *nvdAPIKey
	}

	s := scanner.New()
	s.ToolVersion = strings.TrimPrefix(Version, "v")
	s.GitHub = githubadvisory.Client{Token: githubAuth}
	s.NVD = nvd.Client{APIKey: nvdAuth}
	report, err := s.Scan(ctx, dir, scanner.Options{NoGitHub: !*githubEnabled, NoNVD: !*nvdEnabled, NoEPSS: *noEPSS, IgnoreRules: ignoreRules})
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if err := output.Write(stdout, report, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if scanner.Exceeds(report, sev, *epssThreshold) {
		return 1
	}
	return 0
}

func runFix(args []string, stdout, stderr io.Writer) int {
	configPath, configExplicit, err := config.PathFromArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := config.Load(configPath, configExplicit)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}

	ignoreRules := copyIgnoreRules(cfg.Ignore.Rules)
	fs := flag.NewFlagSet("goscan fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.String("config", configPath, "configuration file (default config.yml when present)")
	apply := fs.Bool("apply", false, "apply all available first-fixed-version recommendations")
	runTests := fs.Bool("test", cfg.Fix.RunTests, "run go test ./... after applying fixes")
	githubEnabled := fs.Bool("github", cfg.GitHub.Enabled, "enable GitHub Advisory Database enrichment")
	nvdEnabled := fs.Bool("nvd", cfg.NVD.Enabled, "enable NVD enrichment")
	noGitHub := fs.Bool("no-github", false, "disable GitHub Advisory Database enrichment")
	noNVD := fs.Bool("no-nvd", false, "disable NVD enrichment")
	noEPSS := fs.Bool("no-epss", !cfg.EPSS.Enabled, "disable FIRST EPSS enrichment")
	showIgnored := fs.Bool("show-ignored", cfg.Ignore.Show, "show findings suppressed as false positives")
	showManifests := fs.Bool("show-manifests", cfg.Scan.ShowManifests, "show requirements declared by selected dependency manifests")
	fs.Func("ignore", "ignore advisory ID or module@ID; append =reason if wanted; repeatable", func(value string) error {
		return addIgnoreRule(ignoreRules, value)
	})
	githubToken := fs.String("github-token", "", "GitHub token override; environment variables are safer")
	nvdAPIKey := fs.String("nvd-api-key", "", "NVD API key override; environment variables are safer")
	formatName := fs.String("format", cfg.Output.Format, "output format: terminal, json, sarif")
	timeout := fs.Duration("timeout", cfg.Fix.Timeout, "overall fix/verification timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "goscan fix accepts at most one path")
		return 2
	}

	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	if *noGitHub {
		*githubEnabled = false
	}
	if *noNVD {
		*nvdEnabled = false
	}

	format, err := output.ParseFormat(*formatName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	githubAuth := cfg.GitHub.Token
	if *githubToken != "" {
		githubAuth = *githubToken
	}
	nvdAuth := cfg.NVD.APIKey
	if *nvdAPIKey != "" {
		nvdAuth = *nvdAPIKey
	}

	s := scanner.New()
	s.ToolVersion = strings.TrimPrefix(Version, "v")
	s.GitHub = githubadvisory.Client{Token: githubAuth}
	s.NVD = nvd.Client{APIKey: nvdAuth}
	opts := scanner.Options{NoGitHub: !*githubEnabled, NoNVD: !*nvdEnabled, NoEPSS: *noEPSS, IgnoreRules: ignoreRules}
	report, err := s.Scan(ctx, dir, opts)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if !*apply || len(report.Findings) == 0 {
		if err := output.Write(stdout, report, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}

	if err := (fixer.Applier{}).Apply(ctx, report.Root, report.Findings, *runTests); err != nil {
		fmt.Fprintln(stderr, "goscan fix:", err)
		return 2
	}
	fmt.Fprintln(stderr, "goscan: fixes applied; rescanning")
	post, err := s.Scan(ctx, dir, opts)
	if err != nil {
		fmt.Fprintln(stderr, "goscan rescan:", err)
		return 2
	}
	if err := output.Write(stdout, post, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(post.Findings) > 0 {
		return 1
	}
	return 0
}

func copyIgnoreRules(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, reason := range in {
		out[key] = reason
	}
	return out
}

func addIgnoreRule(rules map[string]string, value string) error {
	key, reason, hasReason := strings.Cut(strings.TrimSpace(value), "=")
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("--ignore requires an advisory ID or module@ID")
	}
	if !hasReason {
		reason = "ignored from CLI"
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("--ignore reason cannot be empty")
	}
	rules[key] = reason
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `GoSCAn - Go dependency vulnerability scanner and remediation planner

Usage:
  goscan [scan] [flags] [path]
  goscan fix [flags] [path]
  goscan version
  goscan -v

Scan every selected direct, indirect, and transitive Go module using OSV,
enrich advisories with GitHub, NVD, and EPSS data, inspect requirements from
each selected dependency manifest, and recommend the first fixed version.
Transitive fixes include an explicit go.mod // indirect pin when Go MVS can
select the fixed version from the main module.

Examples:
  goscan
  goscan scan --fail-on=high
  goscan scan --format=json
  goscan scan --no-nvd --no-github
  goscan scan --ignore GO-2026-1234
  goscan scan --show-ignored
  goscan scan --show-manifests
  goscan scan --config=config.yml
  goscan scan --format=sarif > goscan.sarif
  goscan fix
  goscan fix --apply`)
}
