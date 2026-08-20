package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	data := []byte(`github:
  enabled: false
  token: "file-token"
nvd:
  enabled: true
  api_key: "nvd-file"
epss:
  enabled: false
ignore:
  show: true
  GO-2026-1234: "not reachable in our build"
  example.com/deep@CVE-2026-9999: "not affected on supported targets"
health:
  enabled: true
  check_go: true
  stale_after_days: 365
  fail_on_outdated_go: true
  fail_on_unmaintained: true
scan:
  fail_on: "high"
  epss_threshold: 0.2
  show_manifests: true
  strict_enrichment: true
  timeout: "45s"
fix:
  run_tests: false
  vulnerabilities: false
  upgrade_go: true
  upgrade_toolchain: true
  timeout: "3m"
output:
  format: "json"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.Enabled || cfg.GitHub.Token != "file-token" || !cfg.NVD.Enabled || cfg.NVD.APIKey != "nvd-file" {
		t.Fatalf("unexpected source config: %#v", cfg)
	}
	if cfg.EPSS.Enabled || !cfg.Ignore.Show || len(cfg.Ignore.Rules) != 2 || cfg.Ignore.Rules["GO-2026-1234"] != "not reachable in our build" {
		t.Fatalf("unexpected ignore config: %#v", cfg.Ignore)
	}
	if !cfg.Health.Enabled || !cfg.Health.CheckGo || cfg.Health.StaleAfterDays != 365 || !cfg.Health.FailOnOutdatedGo || !cfg.Health.FailOnUnmaintained {
		t.Fatalf("unexpected health config: %#v", cfg.Health)
	}
	if cfg.Scan.FailOn != "high" || cfg.Scan.EPSSThreshold != 0.2 || !cfg.Scan.ShowManifests || !cfg.Scan.StrictEnrichment || cfg.Scan.Timeout != 45*time.Second {
		t.Fatalf("unexpected scan config: %#v", cfg)
	}
	if cfg.Fix.RunTests || cfg.Fix.Vulnerabilities || !cfg.Fix.UpgradeGo || !cfg.Fix.UpgradeToolchain || cfg.Fix.Timeout != 3*time.Minute || cfg.Output.Format != "json" {
		t.Fatalf("unexpected remaining config: %#v", cfg)
	}
}

func TestEnvironmentOverridesSecrets(t *testing.T) {
	t.Setenv("GOSCAN_GITHUB_TOKEN", "env-github")
	t.Setenv("GOSCAN_NVD_API_KEY", "env-nvd")
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yml"), false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.Token != "env-github" || cfg.NVD.APIKey != "env-nvd" {
		t.Fatalf("environment did not override secrets: %#v", cfg)
	}
}

func TestConfigExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("TEST_GOSCAN_TOKEN", "secret")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("github:\n  token: \"${TEST_GOSCAN_TOKEN}\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.Token != "secret" {
		t.Fatalf("got %q", cfg.GitHub.Token)
	}
}

func TestPathFromArgs(t *testing.T) {
	path, explicit, err := PathFromArgs([]string{"--format=json", "--config", "custom.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "custom.yml" || !explicit {
		t.Fatalf("got path=%q explicit=%v", path, explicit)
	}
}

func TestIgnoreRuleRequiresReason(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("ignore:\n  GO-2026-1234:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("expected empty ignore reason to fail")
	}
}

func TestConfigRejectsUnknownSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("scan:\n  definitely_not_real: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("expected unknown YAML field to fail")
	}
}

func TestConfigRejectsMultipleDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("scan:\n  fail_on: high\n---\nscan:\n  fail_on: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("expected multiple YAML documents to fail")
	}
}

func TestConfigExpansionCannotInjectYAML(t *testing.T) {
	t.Setenv("TEST_GOSCAN_TOKEN", "secret\nscan:\n  fail_on: critical")
	t.Setenv("TEST_GOSCAN_REASON", "accepted\noutput:\n  format: json")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	data := []byte(`github:
  token: "${TEST_GOSCAN_TOKEN}"
ignore:
  CVE-2026-1234: "${TEST_GOSCAN_REASON}"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.Token != "secret\nscan:\n  fail_on: critical" {
		t.Fatalf("token expansion changed: %q", cfg.GitHub.Token)
	}
	if cfg.Scan.FailOn != "none" || cfg.Output.Format != "terminal" {
		t.Fatalf("environment data changed YAML structure: %#v", cfg)
	}
	if got := cfg.Ignore.Rules["CVE-2026-1234"]; got != "accepted\noutput:\n  format: json" {
		t.Fatalf("reason expansion changed: %q", got)
	}
}

func TestConfigRejectsNonPositiveTimeouts(t *testing.T) {
	for name, data := range map[string]string{
		"scan": "scan:\n  timeout: 0s\n",
		"fix":  "fix:\n  timeout: -1s\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, true); err == nil {
				t.Fatal("expected invalid timeout to fail")
			}
		})
	}
}

func TestIgnoreReasonCannotExpandToEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(`ignore:
  CVE-2026-1234: "${GOSCAN_MISSING_REASON}"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("expected empty expanded ignore reason to fail")
	}
}

func TestConfigRejectsInvalidStaleWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("health:\n  stale_after_days: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("expected invalid stale window to fail")
	}
}
