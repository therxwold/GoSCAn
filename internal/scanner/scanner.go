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
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/model"
	"github.com/therxwold/GoSCAn/internal/nvd"
	"github.com/therxwold/GoSCAn/internal/osv"
	"github.com/therxwold/GoSCAn/internal/versionresolver"
)

type dependencyLoader interface {
	Load(context.Context, string) (*dependency.Result, error)
}
type vulnSource interface {
	Query(context.Context, []osv.Target) (map[string][]model.Vulnerability, error)
}
type githubSource interface {
	Query(context.Context, []string) (map[string]githubadvisory.Record, error)
}
type nvdSource interface {
	Query(context.Context, []string) (map[string]nvd.Record, error)
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
	GitHub          githubSource
	NVD             nvdSource
	EPSS            epssSource
	Versions        latestResolver
	Now             func() time.Time
	ToolVersion     string
}

// Options controls optional scan behavior.
type Options struct {
	NoGitHub    bool
	NoNVD       bool
	NoEPSS      bool
	IgnoreRules map[string]string
}

// New returns a Scanner wired to the default Go, OSV, GitHub, NVD, EPSS, and version providers.
func New() *Scanner {
	return &Scanner{
		Dependencies:    dependency.Loader{},
		Vulnerabilities: osv.Client{},
		GitHub:          githubadvisory.Client{},
		NVD:             nvd.Client{},
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
			report.Findings = append(report.Findings, model.Finding{
				Module: m, Vulnerability: v, LatestVersion: latest, Paths: deps.Graph.PathsTo(m.Path, 3),
			})
		}
	}

	s.enrichGitHub(ctx, report, opts)
	s.enrichNVD(ctx, report, opts)
	s.enrichEPSS(ctx, report, opts)
	applyIgnores(report, opts.IgnoreRules)

	for i := range report.Findings {
		f := &report.Findings[i]
		f.Fix = fixer.Recommend(f.Module, f.Vulnerability.Fixed, f.LatestVersion)
		if f.Module.Replace != nil && f.Vulnerability.Fixed != "" {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s is replaced; automatic go.mod remediation was not proposed", f.Module.Path))
		}
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

	sortFindings(report.Findings)
	sortFindings(report.IgnoredFindings)
	report.Warnings = uniqueSorted(report.Warnings)
	return report, nil
}

func applyIgnores(report *model.Report, rules map[string]string) {
	if len(rules) == 0 || len(report.Findings) == 0 {
		return
	}

	active := make([]model.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		rule, reason, ok := matchingIgnoreRule(finding, rules)
		if !ok {
			active = append(active, finding)
			continue
		}
		finding.Ignored = true
		finding.IgnoreRule = rule
		finding.IgnoreReason = reason
		report.IgnoredFindings = append(report.IgnoredFindings, finding)
		report.Summary.Ignored++
	}
	report.Findings = active
}

func matchingIgnoreRule(finding model.Finding, rules map[string]string) (string, string, bool) {
	identifiers := map[string]struct{}{}
	for _, id := range append(append([]string{finding.Vulnerability.ID}, finding.Vulnerability.Aliases...), finding.Vulnerability.CVEs...) {
		if id = strings.TrimSpace(id); id != "" {
			identifiers[strings.ToUpper(id)] = struct{}{}
		}
	}

	modules := map[string]struct{}{strings.ToLower(finding.Module.Path): {}}
	if path, _, ok := finding.Module.ScanTarget(); ok {
		modules[strings.ToLower(path)] = struct{}{}
	}

	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		iScoped := strings.Contains(keys[i], "@")
		jScoped := strings.Contains(keys[j], "@")
		if iScoped != jScoped {
			// Prefer module-scoped rules when both a scoped and global rule match.
			return iScoped
		}
		return keys[i] < keys[j]
	})

	for _, key := range keys {
		module, id := splitIgnoreRule(key)
		if module != "" {
			if _, ok := modules[strings.ToLower(module)]; !ok {
				continue
			}
		}
		if _, ok := identifiers[strings.ToUpper(id)]; ok {
			return key, rules[key], true
		}
	}
	return "", "", false
}

func splitIgnoreRule(rule string) (module, id string) {
	rule = strings.TrimSpace(rule)
	if at := strings.LastIndex(rule, "@"); at > 0 && at < len(rule)-1 {
		return strings.TrimSpace(rule[:at]), strings.TrimSpace(rule[at+1:])
	}
	return "", rule
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Vulnerability.Severity.Rank() != b.Vulnerability.Severity.Rank() {
			return a.Vulnerability.Severity.Rank() > b.Vulnerability.Severity.Rank()
		}
		if a.Module.Path != b.Module.Path {
			return a.Module.Path < b.Module.Path
		}
		return a.Vulnerability.ID < b.Vulnerability.ID
	})
}

func (s *Scanner) enrichGitHub(ctx context.Context, report *model.Report, opts Options) {
	if opts.NoGitHub || s.GitHub == nil || len(report.Findings) == 0 {
		return
	}
	var ids []string
	lookup := make([]string, len(report.Findings))
	for i := range report.Findings {
		lookup[i] = githubLookupID(report.Findings[i].Vulnerability)
		if lookup[i] != "" {
			ids = append(ids, lookup[i])
		}
	}
	records, err := s.GitHub.Query(ctx, ids)
	if err != nil {
		report.Warnings = append(report.Warnings, "GitHub advisory enrichment failed: "+err.Error())
	}
	for i := range report.Findings {
		r, ok := records[lookup[i]]
		if !ok {
			continue
		}
		v := &report.Findings[i].Vulnerability
		v.Sources = appendSource(v.Sources, model.SourceGitHub)
		v.Aliases = appendIdentifier(v.Aliases, v.ID, r.GHSAID)
		v.Aliases = appendIdentifier(v.Aliases, v.ID, r.CVEID)
		if strings.HasPrefix(r.CVEID, "CVE-") {
			v.CVEs = appendUnique(v.CVEs, r.CVEID)
		}
		if v.Summary == "" {
			v.Summary = r.Summary
		}
		if v.Details == "" {
			v.Details = r.Description
		}
		if path, _, ok := report.Findings[i].Module.ScanTarget(); ok && v.Fixed == "" {
			v.Fixed = r.FirstPatchedByGo[path]
		}
		mergeRisk(v, r.CVSS, r.Severity)
		v.CWEs = appendUniqueAll(v.CWEs, r.CWEs)
		v.References = appendUniqueAll(v.References, r.References)
		sort.Strings(v.Aliases)
		sort.Strings(v.CVEs)
	}
}

func (s *Scanner) enrichNVD(ctx context.Context, report *model.Report, opts Options) {
	if opts.NoNVD || s.NVD == nil || len(report.Findings) == 0 {
		return
	}
	var cves []string
	for _, f := range report.Findings {
		cves = append(cves, f.Vulnerability.CVEs...)
	}
	records, err := s.NVD.Query(ctx, cves)
	if err != nil {
		report.Warnings = append(report.Warnings, "NVD enrichment failed: "+err.Error())
	}
	for i := range report.Findings {
		v := &report.Findings[i].Vulnerability
		for _, cve := range v.CVEs {
			r, ok := records[cve]
			if !ok {
				continue
			}
			v.Sources = appendSource(v.Sources, model.SourceNVD)
			if v.Details == "" {
				v.Details = r.Description
			}
			mergeRisk(v, r.CVSS, r.Severity)
			v.CWEs = appendUniqueAll(v.CWEs, r.CWEs)
			v.References = appendUniqueAll(v.References, r.References)
			v.KnownExploited = v.KnownExploited || r.KnownExploited
		}
	}
}

func (s *Scanner) enrichEPSS(ctx context.Context, report *model.Report, opts Options) {
	if opts.NoEPSS || s.EPSS == nil || len(report.Findings) == 0 {
		return
	}
	var cves []string
	for _, f := range report.Findings {
		cves = append(cves, f.Vulnerability.CVEs...)
	}
	if len(cves) == 0 {
		return
	}
	scores, err := s.EPSS.Query(ctx, cves)
	if err != nil {
		report.Warnings = append(report.Warnings, "EPSS enrichment failed: "+err.Error())
		return
	}
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

func githubLookupID(v model.Vulnerability) string {
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "GHSA-") {
			return id
		}
	}
	for _, id := range v.CVEs {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return ""
}

func mergeRisk(v *model.Vulnerability, candidate *model.CVSS, severity model.Severity) {
	if candidate != nil && (v.CVSS == nil || candidate.Score > v.CVSS.Score) {
		copy := *candidate
		v.CVSS = &copy
		v.Severity = severityFromScore(candidate.Score)
		return
	}
	if severity.Rank() > v.Severity.Rank() {
		v.Severity = severity
	}
}

func severityFromScore(score float64) model.Severity {
	switch {
	case score >= 9:
		return model.SeverityCritical
	case score >= 7:
		return model.SeverityHigh
	case score >= 4:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func appendSource(in []model.AdvisorySource, source model.AdvisorySource) []model.AdvisorySource {
	for _, existing := range in {
		if existing == source {
			return in
		}
	}
	return append(in, source)
}

func appendIdentifier(in []string, primary, id string) []string {
	if id == "" || id == primary {
		return in
	}
	return appendUnique(in, id)
}

func appendUniqueAll(in []string, values []string) []string {
	for _, value := range values {
		in = appendUnique(in, value)
	}
	sort.Strings(in)
	return in
}

func appendUnique(in []string, value string) []string {
	if value == "" {
		return in
	}
	for _, existing := range in {
		if existing == value {
			return in
		}
	}
	return append(in, value)
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
