package scanner

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/therxwold/GoSCAn/internal/dependency"
	"github.com/therxwold/GoSCAn/internal/epss"
	"github.com/therxwold/GoSCAn/internal/fixer"
	"github.com/therxwold/GoSCAn/internal/githubadvisory"
	"github.com/therxwold/GoSCAn/internal/githubrepo"
	"github.com/therxwold/GoSCAn/internal/gorelease"
	"github.com/therxwold/GoSCAn/internal/goversion"
	"github.com/therxwold/GoSCAn/internal/model"
	"github.com/therxwold/GoSCAn/internal/nvd"
	"github.com/therxwold/GoSCAn/internal/osv"
	"github.com/therxwold/GoSCAn/internal/reachability"
	"github.com/therxwold/GoSCAn/internal/versionresolver"
	"golang.org/x/sync/errgroup"
)

// maxConcurrentVersionQueries bounds Go subprocess and proxy pressure during health checks.
const maxConcurrentVersionQueries = 8

// dependencyLoader supplies the selected module graph and package inventory.
type dependencyLoader interface {
	Load(context.Context, string) (*dependency.Result, error)
}

// vulnSource finds vulnerabilities for selected module targets.
type vulnSource interface {
	Query(context.Context, []osv.Target) (map[string][]model.Vulnerability, error)
}

// githubSource supplies GitHub advisory enrichment records.
type githubSource interface {
	Query(context.Context, []string) (map[string]githubadvisory.Record, error)
}

// nvdSource supplies NVD enrichment records.
type nvdSource interface {
	Query(context.Context, []string) (map[string]nvd.Record, error)
}

// epssSource supplies exploit-probability scores for CVEs.
type epssSource interface {
	Query(context.Context, []string) (map[string]model.EPSS, error)
}

// latestResolver resolves the newest available version of a module.
type latestResolver interface {
	Latest(context.Context, string, string) (string, error)
}

// goReleaseSource resolves the newest stable Go release.
type goReleaseSource interface {
	Latest(context.Context) (gorelease.Release, error)
}

// repositorySource supplies dependency maintenance metadata.
type repositorySource interface {
	Query(context.Context, []string, time.Time) (map[string]githubrepo.Record, error)
}

// reachabilitySource supplies source-level vulnerable call evidence.
type reachabilitySource interface {
	Analyze(context.Context, string) (map[string]reachability.Evidence, error)
}

// Scanner orchestrates dependency discovery, vulnerability lookup, risk enrichment, and remediation planning.
type Scanner struct {
	Dependencies    dependencyLoader
	Vulnerabilities vulnSource
	GitHub          githubSource
	NVD             nvdSource
	EPSS            epssSource
	Versions        latestResolver
	GoReleases      goReleaseSource
	Repositories    repositorySource
	Reachability    reachabilitySource
	Now             func() time.Time
	ToolVersion     string
}

// Options controls optional scan behavior.
type Options struct {
	NoGitHub              bool
	NoNVD                 bool
	NoEPSS                bool
	StrictEnrichment      bool
	RequireEPSS           bool
	NoGoVersion           bool
	NoHealth              bool
	RequireCurrentGo      bool
	RequireMaintained     bool
	RequireLatestVersions bool
	NoReachability        bool
	StaleAfter            time.Duration
	IgnoreRules           map[string]model.IgnoreRule
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
		GoReleases:      gorelease.Client{},
		Repositories:    githubrepo.Client{},
		Reachability:    reachability.Analyzer{},
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
	report := &model.Report{
		SchemaVersion: model.ReportSchemaVersion,
		Root:          deps.Root, ToolVersion: s.ToolVersion, Module: deps.MainModule,
		MainRequirements: deps.MainRequirements, PackageAnalysis: deps.PackageAnalysis,
		ScannedAt: s.now().UTC(),
		Integrity: &deps.Integrity,
	}
	report.Warnings = append(report.Warnings, deps.Warnings...)
	if deps.Integrity.MissingGoSum {
		report.Warnings = append(report.Warnings, "go.sum is missing for a module with dependencies")
	}
	if deps.Integrity.Error != "" {
		report.Warnings = append(report.Warnings, "go mod verify failed: "+deps.Integrity.Error)
	}
	if err := s.checkGoVersion(ctx, deps, report, opts); err != nil {
		if opts.StrictEnrichment || opts.RequireCurrentGo {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}

	moduleByKey := map[string]model.Module{}
	var targets []osv.Target
	// Build OSV targets from the exact MVS-selected versions and package sets.
	for _, m := range deps.Modules {
		if m.Main {
			continue
		}
		report.Dependencies = append(report.Dependencies, m)
		report.Summary.Modules++
		if m.ManifestAudited {
			report.Summary.Manifests++
		} else {
			report.Summary.ManifestErrors++
		}
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
		packages := remapPackagePaths(deps.Packages[m.Path], m.Path, path)
		targets = append(targets, osv.Target{
			Key: key, Path: path, Version: version,
			Packages: packages, PackagesKnown: deps.PackageAnalysis,
		})
	}

	if err := s.enrichDependencyHealth(ctx, deps, report, opts); err != nil {
		if opts.StrictEnrichment || opts.RequireMaintained || opts.RequireLatestVersions {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}

	// OSV remains authoritative; optional sources below only enrich these findings.
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
			// Advisory import metadata may narrow a runtime module to a test-only
			// finding when the affected package is imported exclusively by tests.
			findingModule := m
			findingModule.Scope = vulnerabilityScope(v, m.Scope,
				remapPackagePaths(deps.RuntimePackages[m.Path], m.Path, target.Path),
				remapPackagePaths(deps.TestPackages[m.Path], m.Path, target.Path))
			reachability := model.ReachabilityModule
			if findingModule.Scope == model.ScopeRuntime || findingModule.Scope == model.ScopeTestOnly {
				reachability = model.ReachabilityPackage
			}
			report.Findings = append(report.Findings, model.Finding{
				Module: findingModule, Vulnerability: v, LatestVersion: latest,
				Paths: deps.Graph.PathsTo(m.Path, 3), Reachability: reachability,
			})
		}
	}
	if err := s.enrichReachability(ctx, report, opts); err != nil {
		if opts.StrictEnrichment {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}

	if err := s.enrichGitHub(ctx, report, opts); err != nil {
		if opts.StrictEnrichment {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}
	if err := s.enrichNVD(ctx, report, opts); err != nil {
		if opts.StrictEnrichment {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}
	if err := s.enrichEPSS(ctx, report, opts); err != nil {
		if opts.StrictEnrichment || opts.RequireEPSS {
			return nil, err
		}
		report.Warnings = append(report.Warnings, err.Error())
	}
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

	sort.SliceStable(report.Dependencies, func(i, j int) bool {
		return report.Dependencies[i].Path < report.Dependencies[j].Path
	})
	sortFindings(report.Findings)
	sortFindings(report.IgnoredFindings)
	report.Warnings = uniqueSorted(report.Warnings)
	return report, nil
}

// vulnerabilityScope classifies a finding using its affected package metadata.
func vulnerabilityScope(v model.Vulnerability, fallback model.DependencyScope, runtimePackages, testPackages []string) model.DependencyScope {
	if len(v.AffectedImports) == 0 {
		return fallback
	}
	runtime := make(map[string]struct{}, len(runtimePackages))
	tests := make(map[string]struct{}, len(testPackages))
	for _, pkg := range runtimePackages {
		runtime[pkg] = struct{}{}
	}
	for _, pkg := range testPackages {
		tests[pkg] = struct{}{}
	}
	for _, imported := range v.AffectedImports {
		if _, ok := runtime[imported.Path]; ok {
			return model.ScopeRuntime
		}
	}
	for _, imported := range v.AffectedImports {
		if _, ok := tests[imported.Path]; ok {
			return model.ScopeTestOnly
		}
	}
	return fallback
}

// enrichReachability merges govulncheck evidence into matching report findings.
func (s *Scanner) enrichReachability(ctx context.Context, report *model.Report, opts Options) error {
	if opts.NoReachability || s.Reachability == nil || len(report.Findings) == 0 {
		return nil
	}
	evidence, err := s.Reachability.Analyze(ctx, report.Root)
	if err != nil {
		return fmt.Errorf("reachability analysis failed: %w", err)
	}
	for i := range report.Findings {
		finding := &report.Findings[i]
		for _, id := range findingIdentifiers(*finding) {
			e, ok := evidence[id]
			if !ok {
				continue
			}
			if reachabilityRank(e.Level) > reachabilityRank(finding.Reachability) {
				finding.Reachability = e.Level
			}
			finding.CallStacks = append(finding.CallStacks, e.CallStacks...)
		}
	}
	return nil
}

// findingIdentifiers returns every primary and alias identifier for a finding.
func findingIdentifiers(f model.Finding) []string {
	ids := []string{f.Vulnerability.ID}
	ids = append(ids, f.Vulnerability.Aliases...)
	ids = append(ids, f.Vulnerability.CVEs...)
	return ids
}

// reachabilityRank orders module, package, symbol, and called evidence by strength.
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

// remapPackagePaths translates original import paths to a versioned replacement target.
func remapPackagePaths(packages []string, modulePath, targetPath string) []string {
	out := make([]string, 0, len(packages))
	for _, pkg := range packages {
		if modulePath != targetPath && (pkg == modulePath || strings.HasPrefix(pkg, modulePath+"/")) {
			pkg = targetPath + strings.TrimPrefix(pkg, modulePath)
		}
		out = append(out, pkg)
	}
	return out
}

// checkGoVersion compares module directives with the newest stable Go release.
func (s *Scanner) checkGoVersion(ctx context.Context, deps *dependency.Result, report *model.Report, opts Options) error {
	if opts.NoGoVersion {
		return nil
	}
	if s.GoReleases == nil {
		if opts.RequireCurrentGo {
			return fmt.Errorf("Go release check is required but no release source is configured")
		}
		return nil
	}
	release, err := s.GoReleases.Latest(ctx)
	if err != nil {
		return fmt.Errorf("Go release check failed: %w", err)
	}
	goHealth := &model.GoHealth{
		Directive:            deps.GoDirective,
		Toolchain:            deps.Toolchain,
		Latest:               release.Version,
		RecommendedDirective: release.LanguageVersion,
	}
	if deps.GoDirective != "" {
		goHealth.DirectiveOutdated = gorelease.LanguageCompare(deps.GoDirective, release.LanguageVersion) < 0
		goHealth.Unsupported = !gorelease.Supported(deps.GoDirective, release.LanguageVersion)
	}
	if deps.Toolchain != "" && deps.Toolchain != "default" {
		goHealth.ToolchainUpgradeEligible = true
		goHealth.RecommendedToolchain = release.Version
		goHealth.ToolchainOutdated = gorelease.ToolchainCompare(deps.Toolchain, release.Version) < 0
	}
	report.Go = goHealth
	return nil
}

// enrichDependencyHealth evaluates version freshness, retractions, and repository maintenance.
func (s *Scanner) enrichDependencyHealth(ctx context.Context, deps *dependency.Result, report *model.Report, opts Options) error {
	if opts.NoHealth {
		return nil
	}
	staleAfter := opts.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 730 * 24 * time.Hour
	}
	cutoff := s.now().Add(-staleAfter)

	latest := map[string]string{}
	var latestMu sync.Mutex
	var warningMu sync.Mutex
	var latestErr error
	// Resolve independent modules concurrently while bounding subprocess,
	// network, and goroutine pressure for large build lists.
	var group errgroup.Group
	group.SetLimit(maxConcurrentVersionQueries)
	for _, module := range report.Dependencies {
		path, version, ok := module.ScanTarget()
		if !ok || s.Versions == nil {
			continue
		}
		group.Go(func() error {
			v, err := s.Versions.Latest(ctx, deps.Root, path)
			if err != nil {
				warningMu.Lock()
				report.Warnings = append(report.Warnings, err.Error())
				if opts.RequireLatestVersions && (!deps.PackageAnalysis || module.PackagesLoaded) && latestErr == nil {
					latestErr = err
				}
				warningMu.Unlock()
				return nil
			}
			if goversion.Compare(v, version) >= 0 {
				latestMu.Lock()
				latest[path] = v
				latestMu.Unlock()
			}
			return nil
		})
	}
	group.Wait()
	if opts.RequireLatestVersions {
		if s.Versions == nil && len(report.Dependencies) > 0 {
			return fmt.Errorf("latest dependency versions are required but no version resolver is configured")
		}
		if latestErr != nil {
			return fmt.Errorf("resolve latest dependency versions: %w", latestErr)
		}
	}

	modulePaths := make([]string, 0, len(report.Dependencies))
	for _, module := range report.Dependencies {
		path, _, ok := module.ScanTarget()
		if ok {
			modulePaths = append(modulePaths, path)
		}
	}
	repositories := map[string]githubrepo.Record{}
	var repoErr error
	if s.Repositories != nil {
		repositories, repoErr = s.Repositories.Query(ctx, modulePaths, cutoff)
	} else if opts.RequireMaintained {
		repoErr = fmt.Errorf("GitHub repository health source is not configured")
	}

	for _, module := range report.Dependencies {
		path, version, ok := module.ScanTarget()
		if !ok {
			continue
		}
		var paths [][]model.ModuleRef
		if deps.Graph != nil {
			paths = deps.Graph.PathsTo(module.Path, 3)
		}
		health := model.DependencyHealth{
			Module:         model.ModuleRef{Path: module.Path, Version: module.Version},
			Kind:           module.Kind,
			PackagesLoaded: module.PackagesLoaded,
			Paths:          paths,
			Deprecated:     module.Deprecated,
			Retracted:      append([]string(nil), module.Retracted...),
		}
		if latestVersion := latest[path]; latestVersion != "" {
			health.LatestVersion = latestVersion
			health.Outdated = goversion.Compare(version, latestVersion) < 0
		}
		if repo, ok := githubrepo.RepositoryFromModule(path); ok {
			health.Repository = repo
			if record, ok := repositories[repo]; ok {
				health.RepositoryURL = record.URL
				health.Archived = record.Archived
				health.LastPush = record.PushedAt
				health.Stale = !record.PushedAt.IsZero() && record.PushedAt.Before(cutoff)
				health.Unmaintained = record.Archived || record.ExplicitUnmaintained
				health.MaintenanceNotice = record.MaintenanceNotice
			}
		}
		if health.Deprecated != "" {
			report.Summary.Deprecated++
		}
		if len(health.Retracted) > 0 {
			report.Summary.Retracted++
		}
		if health.Outdated {
			report.Summary.OutdatedDependencies++
		}
		if health.Archived {
			report.Summary.Archived++
		}
		if health.Stale {
			report.Summary.Stale++
		}
		if health.Unmaintained {
			report.Summary.Unmaintained++
		}
		if health.Deprecated != "" || len(health.Retracted) > 0 || health.Outdated || health.Archived || health.Stale || health.Unmaintained {
			report.Health = append(report.Health, health)
		}
	}
	sort.SliceStable(report.Health, func(i, j int) bool { return report.Health[i].Module.Path < report.Health[j].Module.Path })
	if repoErr != nil {
		return fmt.Errorf("dependency maintenance check failed: %w", repoErr)
	}
	return nil
}

// HealthExceeds reports whether configured runtime or maintenance policies should fail CI.
func HealthExceeds(report *model.Report, requireCurrentGo, requireMaintained bool) bool {
	if report == nil {
		return false
	}
	if requireCurrentGo && report.Go != nil && (report.Go.DirectiveOutdated || report.Go.ToolchainOutdated || report.Go.Unsupported) {
		return true
	}
	if requireMaintained && report.Summary.Unmaintained > 0 {
		return true
	}
	return false
}

// applyIgnores moves findings covered by active exception rules into the ignored set.
func applyIgnores(report *model.Report, rules map[string]model.IgnoreRule) {
	if len(rules) == 0 || len(report.Findings) == 0 {
		return
	}

	active := make([]model.Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		ruleKey, rule, ok := matchingIgnoreRule(finding, rules)
		if !ok {
			active = append(active, finding)
			continue
		}
		if rule.Expires != "" {
			// Invalid or expired exceptions fail open: the vulnerability stays active.
			expires, err := time.Parse("2006-01-02", rule.Expires)
			if err != nil {
				finding.IgnoreRule = ruleKey
				finding.IgnoreReason = rule.Reason
				finding.IgnoreOwner = rule.Owner
				finding.IgnoreExpires = rule.Expires
				finding.IgnoreExpired = true
				report.Warnings = append(report.Warnings, fmt.Sprintf("ignore rule %s has invalid expiration %q", ruleKey, rule.Expires))
				active = append(active, finding)
				continue
			}
			if !report.ScannedAt.Before(expires.Add(24 * time.Hour)) {
				finding.IgnoreRule = ruleKey
				finding.IgnoreReason = rule.Reason
				finding.IgnoreOwner = rule.Owner
				finding.IgnoreExpires = rule.Expires
				finding.IgnoreExpired = true
				report.Warnings = append(report.Warnings, fmt.Sprintf("ignore rule %s expired on %s", ruleKey, rule.Expires))
				active = append(active, finding)
				continue
			}
		}
		finding.Ignored = true
		finding.IgnoreRule = ruleKey
		finding.IgnoreReason = rule.Reason
		finding.IgnoreOwner = rule.Owner
		finding.IgnoreExpires = rule.Expires
		report.IgnoredFindings = append(report.IgnoredFindings, finding)
		report.Summary.Ignored++
	}
	report.Findings = active
}

// matchingIgnoreRule finds the most specific exception matching a finding or alias.
func matchingIgnoreRule(finding model.Finding, rules map[string]model.IgnoreRule) (string, model.IgnoreRule, bool) {
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
	return "", model.IgnoreRule{}, false
}

// splitIgnoreRule separates an optional module scope from an advisory identifier.
func splitIgnoreRule(rule string) (module, id string) {
	rule = strings.TrimSpace(rule)
	if at := strings.LastIndex(rule, "@"); at > 0 && at < len(rule)-1 {
		return strings.TrimSpace(rule[:at]), strings.TrimSpace(rule[at+1:])
	}
	return "", rule
}

// sortFindings orders findings by severity, module path, and advisory ID.
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

// enrichGitHub merges reviewed GitHub advisory metadata into active findings.
func (s *Scanner) enrichGitHub(ctx context.Context, report *model.Report, opts Options) error {
	if opts.NoGitHub || s.GitHub == nil || len(report.Findings) == 0 {
		return nil
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
		return fmt.Errorf("GitHub advisory enrichment failed: %w", err)
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
	return nil
}

// enrichNVD merges CVSS, CWE, reference, and known-exploitation metadata.
func (s *Scanner) enrichNVD(ctx context.Context, report *model.Report, opts Options) error {
	if opts.NoNVD || s.NVD == nil || len(report.Findings) == 0 {
		return nil
	}
	var cves []string
	for _, f := range report.Findings {
		cves = append(cves, f.Vulnerability.CVEs...)
	}
	records, err := s.NVD.Query(ctx, cves)
	if err != nil {
		return fmt.Errorf("NVD enrichment failed: %w", err)
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
	return nil
}

// enrichEPSS attaches the highest available exploit-probability score to each finding.
func (s *Scanner) enrichEPSS(ctx context.Context, report *model.Report, opts Options) error {
	if opts.NoEPSS || s.EPSS == nil || len(report.Findings) == 0 {
		return nil
	}
	var cves []string
	for _, f := range report.Findings {
		cves = append(cves, f.Vulnerability.CVEs...)
	}
	if len(cves) == 0 {
		return nil
	}
	scores, err := s.EPSS.Query(ctx, cves)
	if err != nil {
		return fmt.Errorf("EPSS enrichment failed: %w", err)
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
	return nil
}

// githubLookupID chooses the best GHSA or CVE identifier for GitHub enrichment.
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

// mergeRisk retains the strongest CVSS-backed or categorical risk information.
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

// severityFromScore maps a CVSS base score to normalized severity.
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

// appendSource adds a provenance source only once.
func appendSource(in []model.AdvisorySource, source model.AdvisorySource) []model.AdvisorySource {
	if slices.Contains(in, source) {
		return in
	}
	return append(in, source)
}

// appendIdentifier adds a non-empty alias distinct from the primary identifier.
func appendIdentifier(in []string, primary, id string) []string {
	if id == "" || id == primary {
		return in
	}
	return appendUnique(in, id)
}

// appendUniqueAll merges values into a sorted duplicate-free slice.
func appendUniqueAll(in []string, values []string) []string {
	for _, value := range values {
		in = appendUnique(in, value)
	}
	sort.Strings(in)
	return in
}

// appendUnique adds a non-empty string only when it is absent.
func appendUnique(in []string, value string) []string {
	if value == "" {
		return in
	}
	if slices.Contains(in, value) {
		return in
	}
	return append(in, value)
}

// now returns the injected clock value or the current system time.
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

// uniqueSorted removes empty and duplicate strings and sorts the result.
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
