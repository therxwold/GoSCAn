package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/model"
	"go.yaml.in/yaml/v3"
)

// Config contains GoSCAn runtime settings loaded from config.yml, environment variables, and CLI flags.
type Config struct {
	GitHub  GitHubConfig
	NVD     NVDConfig
	EPSS    EPSSConfig
	Ignore  IgnoreConfig
	Health  HealthConfig
	Scan    ScanConfig
	Fix     FixConfig
	Output  OutputConfig
	Logging LoggingConfig
}

// GitHubConfig controls GitHub Advisory Database enrichment.
type GitHubConfig struct {
	Enabled bool
	Token   string
}

// NVDConfig controls NVD CVE enrichment.
type NVDConfig struct {
	Enabled bool
	APIKey  string
}

// EPSSConfig controls FIRST EPSS enrichment.
type EPSSConfig struct {
	Enabled bool
}

// IgnoreConfig contains accepted false-positive rules and display preferences.
type IgnoreConfig struct {
	Show  bool
	Rules map[string]model.IgnoreRule
}

// HealthConfig controls Go runtime and dependency maintenance checks.
type HealthConfig struct {
	Enabled            bool
	CheckGo            bool
	StaleAfterDays     int
	FailOnOutdatedGo   bool
	FailOnUnmaintained bool
}

// ScanConfig contains defaults used by the scan command.
type ScanConfig struct {
	FailOn           string
	EPSSThreshold    float64
	ShowManifests    bool
	StrictEnrichment bool
	Timeout          time.Duration
}

// FixConfig contains defaults used by the fix command.
type FixConfig struct {
	RunTests         bool
	Vulnerabilities  bool
	UpgradeGo        bool
	UpgradeToolchain bool
	Timeout          time.Duration
}

// OutputConfig contains report output defaults.
type OutputConfig struct {
	Format string
}

// LoggingConfig controls opt-in Zerolog diagnostics written to stderr.
type LoggingConfig struct {
	Level  string
	Format string
}

// fileConfig mirrors the YAML schema while preserving whether optional fields were set.
type fileConfig struct {
	GitHub *struct {
		Enabled *bool   `yaml:"enabled"`
		Token   *string `yaml:"token"`
	} `yaml:"github"`
	NVD *struct {
		Enabled *bool   `yaml:"enabled"`
		APIKey  *string `yaml:"api_key"`
	} `yaml:"nvd"`
	EPSS *struct {
		Enabled *bool `yaml:"enabled"`
	} `yaml:"epss"`
	Ignore map[string]any `yaml:"ignore"`
	Health *struct {
		Enabled            *bool `yaml:"enabled"`
		CheckGo            *bool `yaml:"check_go"`
		StaleAfterDays     *int  `yaml:"stale_after_days"`
		FailOnOutdatedGo   *bool `yaml:"fail_on_outdated_go"`
		FailOnUnmaintained *bool `yaml:"fail_on_unmaintained"`
	} `yaml:"health"`
	Scan *struct {
		FailOn           *string  `yaml:"fail_on"`
		EPSSThreshold    *float64 `yaml:"epss_threshold"`
		ShowManifests    *bool    `yaml:"show_manifests"`
		StrictEnrichment *bool    `yaml:"strict_enrichment"`
		Timeout          *string  `yaml:"timeout"`
	} `yaml:"scan"`
	Fix *struct {
		RunTests         *bool   `yaml:"run_tests"`
		Vulnerabilities  *bool   `yaml:"vulnerabilities"`
		UpgradeGo        *bool   `yaml:"upgrade_go"`
		UpgradeToolchain *bool   `yaml:"upgrade_toolchain"`
		Timeout          *string `yaml:"timeout"`
	} `yaml:"fix"`
	Output *struct {
		Format *string `yaml:"format"`
	} `yaml:"output"`
	Logging *struct {
		Level  *string `yaml:"level"`
		Format *string `yaml:"format"`
	} `yaml:"logging"`
}

// Default returns GoSCAn's built-in configuration.
func Default() Config {
	return Config{
		GitHub: GitHubConfig{Enabled: true},
		NVD:    NVDConfig{Enabled: true},
		EPSS:   EPSSConfig{Enabled: true},
		Ignore: IgnoreConfig{Rules: map[string]model.IgnoreRule{}},
		Health: HealthConfig{Enabled: true, CheckGo: true, StaleAfterDays: 730},
		Scan: ScanConfig{
			FailOn:        "none",
			EPSSThreshold: -1,
			Timeout:       2 * time.Minute,
		},
		Fix: FixConfig{
			RunTests:        true,
			Vulnerabilities: true,
			Timeout:         5 * time.Minute,
		},
		Output:  OutputConfig{Format: "terminal"},
		Logging: LoggingConfig{Level: "disabled", Format: "text"},
	}
}

// FromEnvironment returns built-in defaults with supported environment overrides applied.
func FromEnvironment() Config {
	cfg := Default()
	applyEnvironment(&cfg)
	return cfg
}

// Load reads an optional YAML configuration file and then applies environment overrides.
// A missing default config.yml is ignored; a missing explicitly selected path is an error.
func Load(path string, explicit bool) (Config, error) {
	cfg := Default()
	if path == "" {
		path = "config.yml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) || explicit {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
	} else if err := decodeYAML(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	applyEnvironment(&cfg)
	return cfg, nil
}

// PathFromArgs returns the config path selected by --config before the main flag set is parsed.
func PathFromArgs(args []string) (path string, explicit bool, err error) {
	for i := range args {
		arg := args[i]
		if after, ok := strings.CutPrefix(arg, "--config="); ok {
			path = strings.TrimSpace(after)
			if path == "" {
				return "", true, fmt.Errorf("--config requires a path")
			}
			return path, true, nil
		}
		if arg == "--config" {
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return "", true, fmt.Errorf("--config requires a path")
			}
			return args[i+1], true, nil
		}
	}
	return "config.yml", false, nil
}

// decodeYAML strictly decodes one YAML document and merges it into cfg.
func decodeYAML(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var raw fileConfig
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	for {
		var extra any
		err := dec.Decode(&extra)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if extra != nil {
			return fmt.Errorf("multiple YAML documents are not supported")
		}
	}
	return mergeFileConfig(cfg, raw)
}

// mergeFileConfig validates and applies explicitly configured file values.
func mergeFileConfig(cfg *Config, raw fileConfig) error {
	if raw.GitHub != nil {
		if raw.GitHub.Enabled != nil {
			cfg.GitHub.Enabled = *raw.GitHub.Enabled
		}
		if raw.GitHub.Token != nil {
			cfg.GitHub.Token = os.ExpandEnv(*raw.GitHub.Token)
		}
	}
	if raw.NVD != nil {
		if raw.NVD.Enabled != nil {
			cfg.NVD.Enabled = *raw.NVD.Enabled
		}
		if raw.NVD.APIKey != nil {
			cfg.NVD.APIKey = os.ExpandEnv(*raw.NVD.APIKey)
		}
	}
	if raw.EPSS != nil && raw.EPSS.Enabled != nil {
		cfg.EPSS.Enabled = *raw.EPSS.Enabled
	}
	if raw.Ignore != nil {
		if cfg.Ignore.Rules == nil {
			cfg.Ignore.Rules = map[string]model.IgnoreRule{}
		}
		for key, value := range raw.Ignore {
			// show belongs to the ignore section but is presentation state rather
			// than an advisory exception.
			if key == "show" {
				show, ok := value.(bool)
				if !ok {
					return fmt.Errorf("ignore.show must be a boolean")
				}
				cfg.Ignore.Show = show
				continue
			}
			rule, err := decodeIgnoreRule(value)
			if err != nil {
				return fmt.Errorf("ignore rule %s: %w", key, err)
			}
			if rule.Reason == "" {
				return fmt.Errorf("ignore rule %s requires a reason", key)
			}
			cfg.Ignore.Rules[strings.TrimSpace(key)] = rule
		}
	}
	if raw.Health != nil {
		if raw.Health.Enabled != nil {
			cfg.Health.Enabled = *raw.Health.Enabled
		}
		if raw.Health.CheckGo != nil {
			cfg.Health.CheckGo = *raw.Health.CheckGo
		}
		if raw.Health.StaleAfterDays != nil {
			if *raw.Health.StaleAfterDays <= 0 {
				return fmt.Errorf("health.stale_after_days must be greater than zero")
			}
			cfg.Health.StaleAfterDays = *raw.Health.StaleAfterDays
		}
		if raw.Health.FailOnOutdatedGo != nil {
			cfg.Health.FailOnOutdatedGo = *raw.Health.FailOnOutdatedGo
		}
		if raw.Health.FailOnUnmaintained != nil {
			cfg.Health.FailOnUnmaintained = *raw.Health.FailOnUnmaintained
		}
	}
	if raw.Scan != nil {
		if raw.Scan.FailOn != nil {
			cfg.Scan.FailOn = *raw.Scan.FailOn
		}
		if raw.Scan.EPSSThreshold != nil {
			cfg.Scan.EPSSThreshold = *raw.Scan.EPSSThreshold
		}
		if raw.Scan.ShowManifests != nil {
			cfg.Scan.ShowManifests = *raw.Scan.ShowManifests
		}
		if raw.Scan.StrictEnrichment != nil {
			cfg.Scan.StrictEnrichment = *raw.Scan.StrictEnrichment
		}
		if raw.Scan.Timeout != nil {
			v, err := time.ParseDuration(*raw.Scan.Timeout)
			if err != nil {
				return fmt.Errorf("scan.timeout: %w", err)
			}
			if v <= 0 {
				return fmt.Errorf("scan.timeout must be greater than zero")
			}
			cfg.Scan.Timeout = v
		}
	}
	if raw.Fix != nil {
		if raw.Fix.RunTests != nil {
			cfg.Fix.RunTests = *raw.Fix.RunTests
		}
		if raw.Fix.Vulnerabilities != nil {
			cfg.Fix.Vulnerabilities = *raw.Fix.Vulnerabilities
		}
		if raw.Fix.UpgradeGo != nil {
			cfg.Fix.UpgradeGo = *raw.Fix.UpgradeGo
		}
		if raw.Fix.UpgradeToolchain != nil {
			cfg.Fix.UpgradeToolchain = *raw.Fix.UpgradeToolchain
		}
		if raw.Fix.Timeout != nil {
			v, err := time.ParseDuration(*raw.Fix.Timeout)
			if err != nil {
				return fmt.Errorf("fix.timeout: %w", err)
			}
			if v <= 0 {
				return fmt.Errorf("fix.timeout must be greater than zero")
			}
			cfg.Fix.Timeout = v
		}
	}
	if raw.Output != nil && raw.Output.Format != nil {
		cfg.Output.Format = *raw.Output.Format
	}
	if raw.Logging != nil {
		if raw.Logging.Level != nil {
			level := strings.ToLower(strings.TrimSpace(*raw.Logging.Level))
			if !oneOf(level, "disabled", "trace", "debug", "info", "warn", "error") {
				return fmt.Errorf("logging.level must be disabled, trace, debug, info, warn, or error")
			}
			cfg.Logging.Level = level
		}
		if raw.Logging.Format != nil {
			format := strings.ToLower(strings.TrimSpace(*raw.Logging.Format))
			if !oneOf(format, "text", "json") {
				return fmt.Errorf("logging.format must be text or json")
			}
			cfg.Logging.Format = format
		}
	}
	return nil
}

// oneOf reports whether value equals one of the allowed strings.
func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// decodeIgnoreRule accepts legacy string rules and structured auditable rules.
func decodeIgnoreRule(value any) (model.IgnoreRule, error) {
	// String rules preserve the original configuration format. Structured rules
	// add ownership and lifecycle metadata without breaking existing files.
	if reason, ok := value.(string); ok {
		return model.IgnoreRule{Reason: strings.TrimSpace(os.ExpandEnv(reason))}, nil
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return model.IgnoreRule{}, fmt.Errorf("requires a reason")
	}
	rule := model.IgnoreRule{}
	for key, raw := range fields {
		text, ok := raw.(string)
		if !ok {
			return model.IgnoreRule{}, fmt.Errorf("%s must be a string", key)
		}
		text = strings.TrimSpace(os.ExpandEnv(text))
		switch key {
		case "reason":
			rule.Reason = text
		case "owner":
			rule.Owner = text
		case "expires":
			if text != "" {
				if _, err := time.Parse("2006-01-02", text); err != nil {
					return model.IgnoreRule{}, fmt.Errorf("expires must use YYYY-MM-DD")
				}
			}
			rule.Expires = text
		default:
			return model.IgnoreRule{}, fmt.Errorf("unknown field %s", key)
		}
	}
	return rule, nil
}

// applyEnvironment overlays supported credential environment variables onto cfg.
func applyEnvironment(cfg *Config) {
	if v := firstEnv("GOSCAN_GITHUB_TOKEN", "GITHUB_TOKEN"); v != "" {
		cfg.GitHub.Token = v
	}
	if v := firstEnv("GOSCAN_NVD_API_KEY", "NVD_API_KEY"); v != "" {
		cfg.NVD.APIKey = v
	}
	if v := firstEnv("GOSCAN_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = strings.ToLower(strings.TrimSpace(v))
	}
	if v := firstEnv("GOSCAN_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = strings.ToLower(strings.TrimSpace(v))
	}
}

// firstEnv returns the first non-empty environment value in priority order.
func firstEnv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
