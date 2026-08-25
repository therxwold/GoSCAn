# GoSCAn

GoSCAn is a Go dependency vulnerability scanner and remediation planner. It
analyzes the complete module build list selected by Go, including direct,
`// indirect`, and transitive dependencies.

Unlike a manifest-only scanner, GoSCAn distinguishes requested versions from
versions actually selected by Minimal Version Selection (MVS), maps runtime and
test package usage, and uses `govulncheck` for vulnerable-symbol and call-path
evidence.

## Highlights

- Queries OSV for every selected versioned Go module.
- Classifies dependencies as direct, indirect, or transitive and scopes loaded
  packages as runtime, test-only, or graph-only.
- Groups GO, GHSA, and CVE aliases into one finding.
- Enriches findings with GitHub advisories, NVD, CVSS, CWE, CISA KEV, and EPSS.
- Audits dependency manifests without confusing requested versions with the
  selected build list.
- Reports retracted, outdated, deprecated, stale, archived, and explicitly
  unmaintained dependencies separately from vulnerabilities.
- Runs official `govulncheck` analysis and displays source-to-sink call paths.
- Supports terminal, JSON, and SARIF output plus alias-aware baselines and
  expiring exceptions.
- Plans minimum-safe or newest-version upgrades and can apply, verify, test,
  rescan, and roll back module-file changes.
- Provides a composite GitHub Action with optional automated remediation pull
  requests.

## Requirements

GoSCAn requires Go 1.26 or newer. Development and release builds prefer the
`toolchain go1.26.6` directive declared by this module.

## Build

```bash
make check
```

The resulting binary is `bin/goscan`. A direct development build is:

```bash
go build -o goscan ./cmd/goscan
```

## Quick start

Scan the current Go module:

```bash
goscan
```

or specify a module directory:

```bash
goscan scan ./service
```

Common operations:

```bash
# Fail CI for High or Critical findings.
goscan scan --fail-on high

# Produce machine-readable reports.
goscan scan --format json > goscan.json
goscan scan --format sarif > goscan.sarif

# Inspect a non-mutating remediation plan.
goscan fix
goscan fix --latest

# Apply the minimum safe fixes and run verification/tests.
goscan fix --apply

# Download the official Go vulnerability database for local govulncheck use.
goscan db update
```

Use `goscan scan --help`, `goscan fix --help`, and `goscan db --help` for the
complete command-line interface.

## Example finding

```text
HIGH  GO-2026-XXXX
  Module:   golang.org/x/net@v0.20.0 (transitive)
  Scope:    runtime
  Evidence: called
  Affected: golang.org/x/net/http2 (processSettingsFrame)
  Fixed:    v0.25.0
  Latest:   v0.44.0
  CVSS:     9.1 (3.1, nvd)
  EPSS:     72.40% (percentile 98.10%)
  Path:
    example.com/app
    └── github.com/example/parent@v1.8.0
    └── golang.org/x/net@v0.20.0
  Fix:      go get golang.org/x/net@v0.25.0
```

GoSCAn recommends the first fixed version for a minimal security repair. The
latest version is shown separately so a larger upgrade remains an explicit
choice. Reachability is evidence and does not automatically hide a selected
vulnerable dependency.

## User documentation

- [Specifications](SPECIFICATIONS.md) explains dependency selection,
  vulnerability matching, reachability, health checks, report contracts, and
  supported boundaries.
- [Configuration](CONFIGURATION.md) covers configuration precedence,
  credentials, providers, ignore rules, and baselines.
- [Remediation](REMEDIATION.md) documents fix planning, latest upgrades,
  application, verification, rollback, and safety.
- [CI integration](CI.md) covers exit codes, policy gates, JSON/SARIF, GitHub
  Actions, and other CI systems.
- [Security and privacy](SECURITY.md) documents network egress, secrets,
  untrusted repositories, local vulnerability data, and enterprise deployment
  considerations.

## Important boundaries

- A normal scan still sends selected module paths and versions to OSV.
- A local vulnerability database currently supplies `govulncheck`; it does not
  make all providers or module loading offline.
- Active `go.work` workspaces are rejected. Scan each module independently with
  `GOWORK=off` until aggregate workspace reporting is implemented.
- Local replacements are not matched to registry advisories. Versioned
  replacements are scanned but are not rewritten automatically.
- `fix --apply` can run repository-controlled Go commands and tests. Use it only
  on trusted repositories and review the resulting dependency changes.

## Development verification

```bash
make release-check
```

This checks module tidiness and checksums, runs the race-enabled test suite and
vet, builds GoSCAn, and scans GoSCAn itself with `govulncheck`.

## Credits

- **Naru K** — creator, architecture, implementation, and documentation.
- **Eluuna** — testing, documentation, and review.

## License

GoSCAn is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE).
