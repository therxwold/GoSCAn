package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/therxwold/GoSCAn/internal/dependency"
	"github.com/therxwold/GoSCAn/internal/epss"
	"github.com/therxwold/GoSCAn/internal/fixer"
	"github.com/therxwold/GoSCAn/internal/model"
	"github.com/therxwold/GoSCAn/internal/osv"
	"github.com/therxwold/GoSCAn/internal/versionresolver"
)

type dependencyLoader interface {
	Load(context.Context, string) (*dependency.Result, error)
}
type vulnSource interface {
	Query(context.Context, []osv.Target) (map[string][]model.Vulnerability, error)
}
type epssSource interface {
	Query(context.Context, []string) (map[string]model.EPSS, error)
}
type latestResolver interface {
	Latest(context.Context, string, string) (string, error)
}

// Scanner orchestrates dependency discovery, vulnerability lookup, risk enrichment, and remediation planning.
type Scanner struct {
	Dependencies    dependencyLoader
	Vulnerabilities vulnSource
	EPSS            epssSource
	Versions        latestResolver
	Now             func() time.Time
	ToolVersion     string
}

// Options controls optional scan behavior.
type Options struct{ NoEPSS bool }

// New returns a Scanner wired to the default Go, OSV, EPSS, and version providers.
func New() *Scanner {
	return &Scanner{
		Dependencies:    dependency.Loader{},
		Vulnerabilities: osv.Client{},
		EPSS:            epss.Client{},
		Versions:        versionresolver.Resolver{},
		Now:             time.Now,
	}
}

// Scan analyzes every selected versioned module below dir and returns a vulnerability report.
func (s *Scanner) Scan(ctx context.Context, dir string, opts Options) (*model.Report, error) {
	if s.Dependencies == nil || s.Vulnerabilities == nil {
		return nil, fmt.Errorf("scanner is not configured")
	}
	deps, err := s.Dependencies.Load(ctx, dir)
	if err != nil {
		return nil, err
	}
	report := &model.Report{Root: deps.Root, ToolVersion: s.ToolVersion, Module: deps.MainModule, ScannedAt: s.now().UTC()}

	moduleByKey := map[string]model.Module{}
	var targets []osv.Target
	for _, m := range deps.Modules {
		if m.Main {
			continue
		}
		report.Summary.Modules++
		switch m.Kind {
		case model.DependencyDirect:
			report.Summary.Direct++
		case model.DependencyIndirect:
			report.Summary.Indirect++
		case model.DependencyTransitive:
			report.Summary.Transitive++
		}
		path, version, ok := m.ScanTarget()
		if !ok {
			report.Summary.Skipped++
			continue
		}
		key := m.Path + "@" + m.Version
		moduleByKey[key] = m
		targets = append(targets, osv.Target{Key: key, Path: path, Version: version})
	}

	found, err := s.Vulnerabilities.Query(ctx, targets)
	if err != nil {
		return nil, err
	}
	latestCache := map[string]string{}
	for _, target := range targets {
		m := moduleByKey[target.Key]
		vulns := found[target.Key]
		if len(vulns) == 0 {
			continue
		}
		latest, ok := latestCache[target.Path]
		if !ok && s.Versions != nil {
			v, err := s.Versions.Latest(ctx, deps.Root, target.Path)
			if err != nil {
				report.Warnings = append(report.Warnings, err.Error())
			} else {
				latest = v
			}
			latestCache[target.Path] = latest
		}
		for _, v := range vulns {
			fix := fixer.Recommend(m, v.Fixed, latest)
			if m.Replace != nil && v.Fixed != "" {
				report.Warnings = append(report.Warnings, fmt.Sprintf("%s is replaced; automatic go.mod remediation was not proposed", m.Path))
			}
			report.Findings = append(report.Findings, model.Finding{Module: m, Vulnerability: v, LatestVersion: latest, Paths: deps.Graph.PathsTo(m.Path, 3), Fix: fix})
		}
	}

	if !opts.NoEPSS && s.EPSS != nil && len(report.Findings) > 0 {
		var cves []string
		for _, f := range report.Findings {
			cves = append(cves, f.Vulnerability.CVEs...)
		}
		if len(cves) > 0 {
			scores, err := s.EPSS.Query(ctx, cves)
			if err != nil {
				report.Warnings = append(report.Warnings, "EPSS enrichment failed: "+err.Error())
			} else {
				for i := range report.Findings {
					var best *model.EPSS
					for _, cve := range report.Findings[i].Vulnerability.CVEs {
						if e, ok := scores[cve]; ok && (best == nil || e.Score > best.Score) {
							copy := e
							best = &copy
						}
					}
					report.Findings[i].Vulnerability.EPSS = best
				}
			}
		}
	}

	for _, f := range report.Findings {
		switch f.Vulnerability.Severity {
		case model.SeverityCritical:
			report.Summary.Critical++
		case model.SeverityHigh:
			report.Summary.High++
		case model.SeverityMedium:
			report.Summary.Medium++
		case model.SeverityLow:
			report.Summary.Low++
		default:
			report.Summary.Unknown++
		}
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Vulnerability.Severity.Rank() != b.Vulnerability.Severity.Rank() {
			return a.Vulnerability.Severity.Rank() > b.Vulnerability.Severity.Rank()
		}
		if a.Module.Path != b.Module.Path {
			return a.Module.Path < b.Module.Path
		}
		return a.Vulnerability.ID < b.Vulnerability.ID
	})
	report.Warnings = uniqueSorted(report.Warnings)
	return report, nil
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Exceeds reports whether a finding crosses the configured severity or EPSS CI threshold.
func Exceeds(report *model.Report, severity model.Severity, epssThreshold float64) bool {
	for _, f := range report.Findings {
		if severity.Rank() > 0 && f.Vulnerability.Severity.Rank() >= severity.Rank() {
			return true
		}
		if epssThreshold >= 0 && f.Vulnerability.EPSS != nil && f.Vulnerability.EPSS.Score >= epssThreshold {
			return true
		}
	}
	return false
}

// ParseSeverity parses a CLI severity threshold.
func ParseSeverity(v string) (model.Severity, error) {
	switch strings.ToLower(v) {
	case "", "none":
		return model.SeverityUnknown, nil
	case "low":
		return model.SeverityLow, nil
	case "medium", "moderate":
		return model.SeverityMedium, nil
	case "high":
		return model.SeverityHigh, nil
	case "critical":
		return model.SeverityCritical, nil
	default:
		return model.SeverityUnknown, fmt.Errorf("invalid severity %q (use none, low, medium, high, or critical)", v)
	}
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, v := range in {
		if v != "" {
			m[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
