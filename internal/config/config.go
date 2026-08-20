package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config contains GoSCAn runtime settings loaded from config.yml, environment variables, and CLI flags.
type Config struct {
	GitHub GitHubConfig
	NVD    NVDConfig
	EPSS   EPSSConfig
	Scan   ScanConfig
	Fix    FixConfig
	Output OutputConfig
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

// ScanConfig contains defaults used by the scan command.
type ScanConfig struct {
	FailOn        string
	EPSSThreshold float64
	Timeout       time.Duration
}

// FixConfig contains defaults used by the fix command.
type FixConfig struct {
	RunTests bool
	Timeout  time.Duration
}

// OutputConfig contains report output defaults.
type OutputConfig struct {
	Format string
}

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
	Scan   *struct {
		FailOn        *string  `yaml:"fail_on"`
		EPSSThreshold *float64 `yaml:"epss_threshold"`
		Timeout       *string  `yaml:"timeout"`
	} `yaml:"scan"`
	Fix *struct {
		RunTests *bool   `yaml:"run_tests"`
		Timeout  *string `yaml:"timeout"`
	} `yaml:"fix"`
	Output *struct {
		Format *string `yaml:"format"`
	} `yaml:"output"`
}

// Default returns GoSCAn's built-in configuration.
func Default() Config {
	return Config{
		GitHub: GitHubConfig{Enabled: true},
		NVD:    NVDConfig{Enabled: true},
		EPSS:   EPSSConfig{Enabled: true},
		Scan: ScanConfig{
			FailOn:        "none",
			EPSSThreshold: -1,
			Timeout:       2 * time.Minute,
		},
		Fix: FixConfig{
			RunTests: true,
			Timeout:  5 * time.Minute,
		},
		Output: OutputConfig{Format: "terminal"},
	}
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
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--config=") {
			path = strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
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

func decodeYAML(data []byte, cfg *Config) error {
	expanded := os.ExpandEnv(string(data))
	dec := yaml.NewDecoder(bytes.NewBufferString(expanded))
	dec.KnownFields(true)

	var raw fileConfig
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("multiple YAML documents are not supported")
	}
	return mergeFileConfig(cfg, raw)
}

func mergeFileConfig(cfg *Config, raw fileConfig) error {
	if raw.GitHub != nil {
		if raw.GitHub.Enabled != nil {
			cfg.GitHub.Enabled = *raw.GitHub.Enabled
		}
		if raw.GitHub.Token != nil {
			cfg.GitHub.Token = *raw.GitHub.Token
		}
	}
	if raw.NVD != nil {
		if raw.NVD.Enabled != nil {
			cfg.NVD.Enabled = *raw.NVD.Enabled
		}
		if raw.NVD.APIKey != nil {
			cfg.NVD.APIKey = *raw.NVD.APIKey
		}
	}
	if raw.EPSS != nil && raw.EPSS.Enabled != nil {
		cfg.EPSS.Enabled = *raw.EPSS.Enabled
	}
	if raw.Scan != nil {
		if raw.Scan.FailOn != nil {
			cfg.Scan.FailOn = *raw.Scan.FailOn
		}
		if raw.Scan.EPSSThreshold != nil {
			cfg.Scan.EPSSThreshold = *raw.Scan.EPSSThreshold
		}
		if raw.Scan.Timeout != nil {
			v, err := time.ParseDuration(*raw.Scan.Timeout)
			if err != nil {
				return fmt.Errorf("scan.timeout: %w", err)
			}
			cfg.Scan.Timeout = v
		}
	}
	if raw.Fix != nil {
		if raw.Fix.RunTests != nil {
			cfg.Fix.RunTests = *raw.Fix.RunTests
		}
		if raw.Fix.Timeout != nil {
			v, err := time.ParseDuration(*raw.Fix.Timeout)
			if err != nil {
				return fmt.Errorf("fix.timeout: %w", err)
			}
			cfg.Fix.Timeout = v
		}
	}
	if raw.Output != nil && raw.Output.Format != nil {
		cfg.Output.Format = *raw.Output.Format
	}
	return nil
}

func applyEnvironment(cfg *Config) {
	if v := firstEnv("GOSCAN_GITHUB_TOKEN", "GITHUB_TOKEN"); v != "" {
		cfg.GitHub.Token = v
	}
	if v := firstEnv("GOSCAN_NVD_API_KEY", "NVD_API_KEY"); v != "" {
		cfg.NVD.APIKey = v
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
