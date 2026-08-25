package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/baseline"
	"github.com/therxwold/GoSCAn/internal/config"
	"github.com/therxwold/GoSCAn/internal/diagnostic"
	"github.com/therxwold/GoSCAn/internal/fixer"
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/githubrepo"
	"github.com/therxwold/GoSCAn/internal/model"
	"github.com/therxwold/GoSCAn/internal/nvd"
	"github.com/therxwold/GoSCAn/internal/output"
	"github.com/therxwold/GoSCAn/internal/reachability"
	"github.com/therxwold/GoSCAn/internal/scanner"
	"github.com/therxwold/GoSCAn/internal/vulndb"
)

// Version is the current GoSCAn version.
const Version string = "v0.4.5"

// Run starts GoSCAn and exits with the command result code.
func Run() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a CLI invocation and returns its process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "-v", "--version", "version":
			goVersion := strings.TrimPrefix(runtime.Version(), "go")
			fmt.Fprintf(stdout, "goscan %s\ngo%s %s/%s\n", Version, goVersion, runtime.GOOS, runtime.GOARCH)
			return 0
		case "help", "-h", "--help":
			usage(stdout)
			return 0
		case "scan":
			return runScan(args[1:], stdout, stderr)
		case "fix":
			return runFix(args[1:], stdout, stderr)
		case "db":
			return runDB(args[1:], stdout, stderr)
		}
	}

	// Bare goscan [flags] [path] behaves like `goscan scan`.
	return runScan(args, stdout, stderr)
}

// runScan parses scan flags, executes one scan, renders its report, and evaluates CI thresholds.
func runScan(args []string, stdout, stderr io.Writer) int {
	cfg, configPath, err := loadCommandConfig(args)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}

	ignoreRules := copyIgnoreRules(cfg.Ignore.Rules)
	fs := flag.NewFlagSet("goscan scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.String("config", configPath, "configuration file (default config.yml when present)")
	_ = fs.Bool("no-config", false, "ignore config.yml and use built-in/environment defaults")
	formatName := fs.String("format", cfg.Output.Format, "output format: terminal, json, sarif")
	jsonAlias := fs.Bool("json", false, "alias for --format=json")
	failOn := fs.String("fail-on", cfg.Scan.FailOn, "exit 1 at or above severity: none, low, medium, high, critical")
	epssThreshold := fs.Float64("epss-threshold", cfg.Scan.EPSSThreshold, "exit 1 when EPSS probability is at least this value (0..1); -1 disables")
	githubEnabled := fs.Bool("github", cfg.GitHub.Enabled, "enable GitHub Advisory Database enrichment")
	nvdEnabled := fs.Bool("nvd", cfg.NVD.Enabled, "enable NVD enrichment")
	noGitHub := fs.Bool("no-github", false, "disable GitHub Advisory Database enrichment")
	noNVD := fs.Bool("no-nvd", false, "disable NVD enrichment")
	noEPSS := fs.Bool("no-epss", !cfg.EPSS.Enabled, "disable FIRST EPSS enrichment")
	noReachability := fs.Bool("no-reachability", false, "disable govulncheck symbol and call-path analysis")
	vulnerabilityDatabase := fs.String("vulndb", defaultVulnerabilityDatabase(), "govulncheck database URL or local directory")
	showIgnored := fs.Bool("show-ignored", cfg.Ignore.Show, "show findings suppressed as false positives")
	showManifests := fs.Bool("show-manifests", cfg.Scan.ShowManifests, "show requirements declared by selected dependency manifests")
	strictEnrichment := fs.Bool("strict-enrichment", cfg.Scan.StrictEnrichment, "fail when an enabled enrichment source is unavailable")
	healthEnabled := fs.Bool("health", cfg.Health.Enabled, "enable dependency maintenance health checks")
	noHealth := fs.Bool("no-health", false, "disable dependency maintenance health checks")
	goVersionEnabled := fs.Bool("go-version", cfg.Health.CheckGo, "check the main module Go version against the latest stable release")
	noGoVersion := fs.Bool("no-go-version", false, "disable Go language/toolchain version checking")
	staleAfterDays := fs.Int("stale-after-days", cfg.Health.StaleAfterDays, "flag GitHub dependencies with no pushes for this many days")
	failOnOutdatedGo := fs.Bool("fail-on-outdated-go", cfg.Health.FailOnOutdatedGo, "exit 1 when the go directive or toolchain is behind current stable Go")
	failOnUnmaintained := fs.Bool("fail-on-unmaintained", cfg.Health.FailOnUnmaintained, "exit 1 when a dependency is explicitly unmaintained or archived")
	fs.Func("ignore", "ignore advisory ID or module@ID; append =reason if wanted; repeatable", func(value string) error {
		return addIgnoreRule(ignoreRules, value)
	})
	timeout := fs.Duration("timeout", cfg.Scan.Timeout, "overall scan timeout")
	baselinePath := fs.String("baseline", "", "compare findings with a saved baseline JSON file")
	saveBaseline := fs.String("save-baseline", "", "save current findings as a baseline JSON file")
	logLevel := fs.String("log-level", cfg.Logging.Level, "diagnostic log level: disabled, trace, debug, info, warn, error")
	logFormat := fs.String("log-format", cfg.Logging.Format, "diagnostic log format: text, json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
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
	if *noHealth {
		*healthEnabled = false
	}
	if *noGoVersion {
		*goVersionEnabled = false
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
	if *noEPSS && *epssThreshold >= 0 {
		fmt.Fprintln(stderr, "--epss-threshold requires EPSS enrichment")
		return 2
	}
	if !*goVersionEnabled && *failOnOutdatedGo {
		fmt.Fprintln(stderr, "--fail-on-outdated-go requires Go version checking")
		return 2
	}
	if !*healthEnabled && *failOnUnmaintained {
		fmt.Fprintln(stderr, "--fail-on-unmaintained requires dependency health checks")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero")
		return 2
	}
	if *staleAfterDays <= 0 {
		fmt.Fprintln(stderr, "--stale-after-days must be greater than zero")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, finishDiagnostics, err := commandContext(ctx, stderr, *logLevel, *logFormat, "scan")
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	defer finishDiagnostics()

	s := scanner.New()
	s.ToolVersion = strings.TrimPrefix(Version, "v")
	s.GitHub = githubadvisory.Client{Token: cfg.GitHub.Token}
	s.NVD = nvd.Client{APIKey: cfg.NVD.APIKey}
	s.Repositories = githubrepo.Client{Token: cfg.GitHub.Token}
	databaseURL := ""
	if !*noReachability {
		databaseURL, err = vulndb.DatabaseURL(*vulnerabilityDatabase)
		if err != nil {
			fmt.Fprintln(stderr, "goscan:", err)
			return 2
		}
	}
	s.Reachability = reachability.Analyzer{DatabaseURL: databaseURL}
	report, err := s.Scan(ctx, dir, scanner.Options{
		NoGitHub: !*githubEnabled, NoNVD: !*nvdEnabled, NoEPSS: *noEPSS,
		StrictEnrichment: *strictEnrichment, RequireEPSS: *epssThreshold >= 0,
		NoHealth: !*healthEnabled, NoGoVersion: !*goVersionEnabled,
		RequireCurrentGo: *failOnOutdatedGo, RequireMaintained: *failOnUnmaintained,
		NoReachability: *noReachability, StaleAfter: time.Duration(*staleAfterDays) * 24 * time.Hour, IgnoreRules: ignoreRules,
	})
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if *baselinePath != "" {
		if err := baseline.Apply(*baselinePath, report); err != nil {
			fmt.Fprintln(stderr, "goscan:", err)
			return 2
		}
	}
	if *saveBaseline != "" {
		if err := baseline.Save(*saveBaseline, report); err != nil {
			fmt.Fprintln(stderr, "goscan:", err)
			return 2
		}
	}
	if err := output.Write(stdout, report, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if scanner.Exceeds(report, sev, *epssThreshold) || scanner.HealthExceeds(report, *failOnOutdatedGo, *failOnUnmaintained) {
		return 1
	}
	return 0
}

// runFix previews or applies remediation and latest-version upgrade plans.
func runFix(args []string, stdout, stderr io.Writer) int {
	cfg, configPath, err := loadCommandConfig(args)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}

	ignoreRules := copyIgnoreRules(cfg.Ignore.Rules)
	fs := flag.NewFlagSet("goscan fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.String("config", configPath, "configuration file (default config.yml when present)")
	_ = fs.Bool("no-config", false, "ignore config.yml and use built-in/environment defaults")
	apply := fs.Bool("apply", false, "apply all available first-fixed-version recommendations")
	latest := fs.Bool("latest", false, "preview newest dependency and Go upgrades; combine with --apply to apply them")
	runTests := fs.Bool("test", cfg.Fix.RunTests, "run go test ./... after applying fixes")
	githubEnabled := fs.Bool("github", cfg.GitHub.Enabled, "enable GitHub Advisory Database enrichment")
	nvdEnabled := fs.Bool("nvd", cfg.NVD.Enabled, "enable NVD enrichment")
	noGitHub := fs.Bool("no-github", false, "disable GitHub Advisory Database enrichment")
	noNVD := fs.Bool("no-nvd", false, "disable NVD enrichment")
	noEPSS := fs.Bool("no-epss", !cfg.EPSS.Enabled, "disable FIRST EPSS enrichment")
	noReachability := fs.Bool("no-reachability", false, "disable govulncheck symbol and call-path analysis")
	vulnerabilityDatabase := fs.String("vulndb", defaultVulnerabilityDatabase(), "govulncheck database URL or local directory")
	showIgnored := fs.Bool("show-ignored", cfg.Ignore.Show, "show findings suppressed as false positives")
	showManifests := fs.Bool("show-manifests", cfg.Scan.ShowManifests, "show requirements declared by selected dependency manifests")
	strictEnrichment := fs.Bool("strict-enrichment", cfg.Scan.StrictEnrichment, "fail when an enabled enrichment source is unavailable")
	healthEnabled := fs.Bool("health", cfg.Health.Enabled, "enable dependency maintenance health checks")
	noHealth := fs.Bool("no-health", false, "disable dependency maintenance health checks")
	goVersionEnabled := fs.Bool("go-version", cfg.Health.CheckGo, "check the main module Go version against the latest stable release")
	noGoVersion := fs.Bool("no-go-version", false, "disable Go language/toolchain version checking")
	staleAfterDays := fs.Int("stale-after-days", cfg.Health.StaleAfterDays, "flag GitHub dependencies with no pushes for this many days")
	fixVulnerabilities := fs.Bool("vulnerabilities", cfg.Fix.Vulnerabilities, "apply available vulnerability fixes")
	upgradeGo := fs.Bool("upgrade-go", cfg.Fix.UpgradeGo, "upgrade the main go directive to the latest stable Go release")
	upgradeToolchain := fs.Bool("upgrade-toolchain", cfg.Fix.UpgradeToolchain, "upgrade an existing toolchain directive to the latest stable Go toolchain")
	fs.Func("ignore", "ignore advisory ID or module@ID; append =reason if wanted; repeatable", func(value string) error {
		return addIgnoreRule(ignoreRules, value)
	})
	formatName := fs.String("format", cfg.Output.Format, "output format: terminal, json, sarif")
	timeout := fs.Duration("timeout", cfg.Fix.Timeout, "overall fix/verification timeout")
	logLevel := fs.String("log-level", cfg.Logging.Level, "diagnostic log level: disabled, trace, debug, info, warn, error")
	logFormat := fs.String("log-format", cfg.Logging.Format, "diagnostic log format: text, json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "goscan fix accepts at most one path")
		return 2
	}
	if *latest && (*noHealth || *noGoVersion) {
		fmt.Fprintln(stderr, "--latest cannot be combined with --no-health or --no-go-version")
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
	if *noHealth {
		*healthEnabled = false
	}
	if *noGoVersion {
		*goVersionEnabled = false
	}
	if *latest {
		*healthEnabled = true
		*goVersionEnabled = true
		*upgradeGo = true
		*upgradeToolchain = true
	}

	format, err := output.ParseFormat(*formatName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero")
		return 2
	}
	if *staleAfterDays <= 0 {
		fmt.Fprintln(stderr, "--stale-after-days must be greater than zero")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, finishDiagnostics, err := commandContext(ctx, stderr, *logLevel, *logFormat, "fix")
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	defer finishDiagnostics()

	s := scanner.New()
	s.ToolVersion = strings.TrimPrefix(Version, "v")
	s.GitHub = githubadvisory.Client{Token: cfg.GitHub.Token}
	s.NVD = nvd.Client{APIKey: cfg.NVD.APIKey}
	s.Repositories = githubrepo.Client{Token: cfg.GitHub.Token}
	databaseURL := ""
	if !*noReachability {
		databaseURL, err = vulndb.DatabaseURL(*vulnerabilityDatabase)
		if err != nil {
			fmt.Fprintln(stderr, "goscan:", err)
			return 2
		}
	}
	s.Reachability = reachability.Analyzer{DatabaseURL: databaseURL}
	opts := scanner.Options{NoGitHub: !*githubEnabled, NoNVD: !*nvdEnabled, NoEPSS: *noEPSS, StrictEnrichment: *strictEnrichment,
		NoHealth: !*healthEnabled, NoGoVersion: !*goVersionEnabled, NoReachability: *noReachability,
		StaleAfter: time.Duration(*staleAfterDays) * 24 * time.Hour, IgnoreRules: ignoreRules}
	if *latest {
		opts.RequireCurrentGo = true
		opts.RequireLatestVersions = true
	}
	report, err := s.Scan(ctx, dir, opts)
	if err != nil {
		fmt.Fprintln(stderr, "goscan:", err)
		return 2
	}
	if *latest {
		report.UpgradePlan = fixer.LatestPlan(report, *fixVulnerabilities)
	}
	if !*apply {
		if err := output.Write(stdout, report, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}

	applier := fixer.Applier{}
	applied := false
	if *latest {
		applied, err = applier.ApplyLatest(ctx, report.Root, report, *fixVulnerabilities, *runTests)
		if err != nil {
			fmt.Fprintln(stderr, "goscan fix:", err)
			return 2
		}
	} else {
		if *fixVulnerabilities && fixer.HasApplicable(report.Findings) {
			if err := applier.Apply(ctx, report.Root, report.Findings, *runTests); err != nil {
				fmt.Fprintln(stderr, "goscan fix:", err)
				return 2
			}
			applied = true
		}
		goApplied, err := applier.ApplyGo(ctx, report.Root, report.Go, *upgradeGo, *upgradeToolchain, *runTests)
		if err != nil {
			fmt.Fprintln(stderr, "goscan fix:", err)
			return 2
		}
		applied = applied || goApplied
	}
	if !applied {
		if err := output.Write(stdout, report, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	fmt.Fprintln(stderr, "goscan: fixes applied; rescanning")
	post, err := s.Scan(ctx, dir, opts)
	if err != nil {
		fmt.Fprintln(stderr, "goscan rescan:", err)
		return 2
	}
	post.UpgradeResult = fixer.UpgradeDiff(report, post)
	if err := output.Write(stdout, post, format, output.WriteOptions{ShowIgnored: *showIgnored, ShowManifests: *showManifests}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(post.Findings) > 0 {
		return 1
	}
	return 0
}

// runDB dispatches vulnerability database management commands.
func runDB(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		databaseUsage(stdout)
		return 0
	}
	if args[0] != "update" {
		fmt.Fprintf(stderr, "goscan db: unknown command %q\n", args[0])
		databaseUsage(stderr)
		return 2
	}
	return runDBUpdate(args[1:], stdout, stderr)
}

// runDBUpdate downloads and installs one official-format Go vulnerability database snapshot.
func runDBUpdate(args []string, stdout, stderr io.Writer) int {
	defaultPath, defaultPathErr := vulndb.DefaultPath()
	loggingDefaults := config.FromEnvironment().Logging
	fs := flag.NewFlagSet("goscan db update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", defaultPath, "database installation directory")
	source := fs.String("url", vulndb.DefaultURL, "database snapshot URL")
	timeout := fs.Duration("timeout", 2*time.Minute, "download and installation timeout")
	logLevel := fs.String("log-level", loggingDefaults.Level, "diagnostic log level: disabled, trace, debug, info, warn, error")
	logFormat := fs.String("log-format", loggingDefaults.Format, "diagnostic log format: text, json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "goscan db update does not accept positional arguments")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero")
		return 2
	}
	if *path == "" && defaultPathErr != nil {
		fmt.Fprintln(stderr, "goscan db update:", defaultPathErr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, finishDiagnostics, err := commandContext(ctx, stderr, *logLevel, *logFormat, "db update")
	if err != nil {
		fmt.Fprintln(stderr, "goscan db update:", err)
		return 2
	}
	defer finishDiagnostics()
	metadata, err := (vulndb.Updater{URL: *source}).Update(ctx, *path)
	if err != nil {
		fmt.Fprintln(stderr, "goscan db update:", err)
		return 2
	}
	fmt.Fprintln(stdout, "Go vulnerability database updated")
	fmt.Fprintf(stdout, "Path:       %s\n", metadata.Path)
	fmt.Fprintf(stdout, "Source:     %s\n", metadata.Source)
	fmt.Fprintf(stdout, "Modified:   %s\n", metadata.Modified.Format(time.RFC3339))
	fmt.Fprintf(stdout, "Advisories: %d\n", metadata.Advisories)
	return 0
}

// commandContext attaches a command-scoped Zerolog logger and returns a
// completion callback that records elapsed time without changing report output.
func commandContext(parent context.Context, stderr io.Writer, level, format, command string) (context.Context, func(), error) {
	logger, err := diagnostic.New(stderr, level, format)
	if err != nil {
		return nil, nil, err
	}
	logger = logger.With().Str("command", command).Str("version", Version).Logger()
	ctx := logger.WithContext(parent)
	started := time.Now()
	logger.Info().Msg("command started")
	finish := func() {
		logger.Info().Dur("duration", time.Since(started)).Msg("command finished")
	}
	return ctx, finish, nil
}

// defaultVulnerabilityDatabase selects an explicit environment override or an installed cache.
func defaultVulnerabilityDatabase() string {
	if value := strings.TrimSpace(os.Getenv("GOSCAN_VULNDB")); value != "" {
		return value
	}
	path, err := vulndb.DefaultPath()
	if err == nil && vulndb.Installed(path) {
		return path
	}
	return ""
}

// loadCommandConfig resolves configuration-selection flags before command-specific flag parsing.
func loadCommandConfig(args []string) (config.Config, string, error) {
	if requestsHelp(args) {
		return config.Default(), "config.yml", nil
	}
	if configDisabled(args) {
		return config.FromEnvironment(), "config.yml", nil
	}
	path, explicit, err := config.PathFromArgs(args)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.Load(path, explicit)
	return cfg, path, err
}

// configDisabled reports whether arguments explicitly disable configuration-file loading.
func configDisabled(args []string) bool {
	for _, arg := range args {
		if arg == "--no-config" || arg == "--no-config=true" {
			return true
		}
	}
	return false
}

// requestsHelp reports whether arguments request command help.
func requestsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

// copyIgnoreRules clones configured rules so CLI additions cannot mutate the loaded configuration.
func copyIgnoreRules(in map[string]model.IgnoreRule) map[string]model.IgnoreRule {
	out := make(map[string]model.IgnoreRule, len(in))
	maps.Copy(out, in)
	return out
}

// addIgnoreRule parses one --ignore value and adds it to the active rule set.
func addIgnoreRule(rules map[string]model.IgnoreRule, value string) error {
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
	rules[key] = model.IgnoreRule{Reason: reason}
	return nil
}

// usage writes the top-level command synopsis and common examples.
func usage(w io.Writer) {
	fmt.Fprintln(w, `GoSCAn - Go dependency vulnerability scanner and remediation planner

Usage:
  goscan [scan] [flags] [path]
  goscan fix [flags] [path]
  goscan db update [flags]
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
  goscan scan --fail-on-outdated-go --fail-on-unmaintained
  goscan scan --config=config.yml
  goscan scan --format=sarif > goscan.sarif
  goscan fix
  goscan fix --apply
  goscan fix --apply --latest
  goscan fix --apply --upgrade-go --upgrade-toolchain
  goscan db update`)
}

// databaseUsage writes help for local Go vulnerability database management.
func databaseUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  goscan db update [flags]

Download, validate, and atomically install the official Go vulnerability
database snapshot. Scans automatically use the default installed snapshot for
govulncheck reachability analysis. Set GOSCAN_VULNDB or --vulndb to select a
different local directory or database URL.

Examples:
  goscan db update
  goscan db update --path /var/cache/goscan/vulndb
  goscan scan --vulndb /var/cache/goscan/vulndb`)
}
