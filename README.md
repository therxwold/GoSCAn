# GoSCAn

GoSCAn is a Go dependency vulnerability scanner and remediation planner. It scans the complete module build list selected by Go MVS, including direct requirements, explicit `// indirect` requirements, and deeper transitive modules.

Its job is not only to say that a dependency is vulnerable. It also explains why that dependency is in the graph, audits requirements declared by selected dependency manifests, finds the first fixed version, resolves the current latest version, cross-checks advisories with GitHub and NVD, enriches CVEs with EPSS exploitation probability, and proposes the smallest useful `go.mod` repair.

## What it does

- Scans **every versioned module selected by `go list -m -json all`** and queries retraction metadata for those exact selected versions.
- Classifies modules as `direct`, `indirect`, or `transitive` for reporting.
- Classifies loaded code as `runtime`, `test-only`, or `graph-only`, including the specific affected package when advisory import metadata is available.
- Builds dependency paths from `go mod graph`.
- Audits every selected dependency's actual `go.mod` with `golang.org/x/mod/modfile`, including the dependency's Go version, requested module version, `// indirect` state, and the version actually selected by MVS.
- Keeps manifest requirements separate from the active `go mod graph`, so pruned or stale declarations cannot invent active dependency paths.
- Queries OSV using the Go ecosystem and the exact selected module version.
- Resolves packages loaded by `./...` and its tests, then uses Go advisory import-path metadata to suppress module-level matches for packages the build does not load. If package analysis is incomplete, scanning falls back conservatively to module-level results.
- Retains vulnerable package and symbol metadata from the Go Vulnerability Database, and runs the official `govulncheck` analyzer to identify called vulnerable symbols and report source-to-sink call paths.
- Cross-checks OSV findings against reviewed GitHub Advisory Database records.
- Enriches CVEs with NVD metadata, CVSS, CWE references, and CISA KEV status when available.
- Groups duplicate OSV/GO/GHSA/CVE aliases into one finding.
- Extracts the first fixed version that closes the vulnerable range containing the selected version.
- Resolves `@latest` for vulnerable modules.
- Parses and calculates CVSS 2.0, 3.0, 3.1, and 4.0 scores with `github.com/pandatix/go-cvss`.
- Fetches FIRST EPSS score and percentile for CVEs.
- Tracks advisory provenance so JSON, SARIF, and terminal output show which sources confirmed a finding.
- Recommends an explicit `// indirect` `go.mod` requirement for vulnerable transitive dependencies when there is a fixed version.
- Supports terminal, JSON, and SARIF output.
- Supports CI policy exits by severity and/or EPSS threshold.
- Supports auditable false-positive ignore rules by GO/GHSA/CVE alias, with optional module scoping, owner, and expiration date.
- Compares scans against saved baselines and classifies findings as new, unchanged, regressed, or resolved.
- Reports retracted selected versions and verifies the module cache with `go mod verify` during every scan.
- Previews latest-version upgrades without modifying files and reports dependency and vulnerability changes after an applied upgrade.
- Can apply fixes with `go get`, run `go mod tidy`, verify downloaded modules, run tests, and roll back `go.mod`/`go.sum` if verification fails.

Local filesystem replacements are intentionally skipped because a registry version no longer identifies the code being built. Versioned `replace` targets are scanned, but GoSCAn does not automatically rewrite replacement directives because guessing the intended replacement scope is unsafe.

## Requirements

GoSCAn requires **Go 1.26 or newer**. The module declares `toolchain go1.26.6`, so development and release builds prefer Go 1.26.6 when Go toolchain switching is available.

GoSCAn intentionally keeps its third-party dependency set small, but it does not reimplement mature parsers or standards logic:

- `go.yaml.in/yaml/v3` parses `config.yml`.
- `golang.org/x/mod` handles `go.mod` parsing and Go semantic-version comparison.
- `golang.org/x/vuln` embeds the official `govulncheck` source analyzer.
- `github.com/pandatix/go-cvss` parses and scores CVSS 2.0, 3.0, 3.1, and 4.0 vectors.

## Build

```bash
make check
```

The resulting binary is `bin/goscan`.

For a local development build:

```bash
go build -o goscan ./cmd/goscan
```

## Versioning

The application version lives in `internal/app/app.go`, next to the CLI/application wiring. Release builds use that version directly rather than maintaining separate build metadata.

All of these work:

```bash
goscan -v
goscan --version
goscan version
```

A release build prints something similar to:

```text
goscan v0.4.0
```

## Scan

Run GoSCAn inside a Go module:

```bash
goscan
```

or:

```bash
goscan scan .
```

Example finding:

```text
HIGH  GO-2026-XXXX
  Module:   golang.org/x/net@v0.20.0 (transitive)
  Scope:    runtime
  Evidence: called
  Affected: golang.org/x/net/http2 (processSettingsFrame)
  Call path:
    example.com/app.main
    └── golang.org/x/net/http2.processSettingsFrame
  Fixed:    v0.25.0
  Latest:   v0.44.0
  CVSS:     9.1 (3.1, nvd)
  EPSS:     72.40% (percentile 98.10%)
  CVE:      CVE-2026-XXXX
  CWE:      CWE-400
  Sources:  osv, github, nvd
  Path:
    example.com/app
    └── github.com/example/parent@v1.8.0
    └── golang.org/x/net@v0.20.0
  Declared by:
    github.com/example/parent@v1.8.0 requires golang.org/x/net@v0.18.0 (selected v0.20.0)
  Fix:      go get golang.org/x/net@v0.25.0
  go.mod recommendation:
    + require golang.org/x/net v0.25.0 // indirect
```

The explicit transitive pin works with Go MVS by raising the minimum selected version in the main module. GoSCAn recommends the **first fixed version**, not `@latest`, as the minimal security repair. The latest version is shown separately so the developer can choose a larger upgrade deliberately. Reachability is evidence, not an automatic suppression: a selected vulnerable module remains visible even when no call path is found.

### Dependency manifest audit

GoSCAn keeps the requested versions declared by selected dependency manifests separate from the versions actually selected by MVS. Show the complete manifest view with:

```bash
goscan scan --show-manifests
```

Example:

```text
Dependency manifests:
  github.com/example/parent@v1.8.0 (direct, go 1.22)
    requires golang.org/x/net@v0.18.0 -> selected v0.20.0
  golang.org/x/net@v0.20.0 (transitive, go 1.20)
    requires: none
```

The left-hand version is what the parent module declares. `selected` is the version Go actually builds. A vulnerable lower version mentioned by a dependency does **not** become an active finding when MVS has already selected a safe higher version. The declaration is retained as provenance and remediation context instead of being promoted into a false positive. JSON always includes this dependency manifest metadata under `dependencies`; `--show-manifests` controls the extra terminal output.


## Go and dependency health

GoSCAn treats maintenance risk separately from known vulnerabilities. By default it checks the main module's `go` directive against the latest stable Go release and inspects **every module in Go's selected build list** for newer versions, Go module deprecation notices, archived GitHub repositories, stale repositories, and explicit upstream maintenance notices. That includes direct requirements, explicit `// indirect` requirements, and deeper transitive dependencies selected through other modules. Dependency-health findings include a path from the main module so the parent that introduced a transitive risk is visible.

GoSCAn discovers the current release from Go's official downloads JSON endpoint (`https://go.dev/dl/?mode=json`), filters stable releases, and chooses the highest version using Go module semver rules. The latest release is therefore not hard-coded into GoSCAn. For example, when the endpoint reports `go1.27.0` as latest, a project that still declares `go 1.18` can produce:

```text
Go version:
  go:        1.18 -> 1.27 (directive predates supported release lines; latest stable go1.27.0)
```

The `go` directive sets the module's minimum language and module semantics; it does not identify the toolchain currently building the project. This status therefore describes the directive's release line, not proof that an unsupported toolchain is in use.

If the main module already has a `toolchain` directive, GoSCAn checks that exact toolchain too and recommends the newest stable toolchain when it is behind. It does not add a `toolchain` directive to projects that do not already use one.

Maintenance findings are not CVEs. A dependency can therefore have no known vulnerability and still be reported as `UNMAINTAINED`, `ARCHIVED`, `STALE`, `DEPRECATED`, `RETRACTED`, or `OUTDATED`. This is intentional. Retraction reasons come from the selected version's module metadata. GoSCAn also runs `go mod verify`; terminal and JSON output record successful verification, a missing `go.sum`, or a checksum/cache failure, while SARIF emits results for the failure states. GoSCAn never promotes a version merely mentioned in a dependency's `go.mod` into an active health or vulnerability finding: the selected MVS build list remains the source of truth.

Useful policy flags:

```bash
goscan scan --fail-on-outdated-go
goscan scan --fail-on-unmaintained
goscan scan --stale-after-days 730
```

The checks can be disabled independently with `--no-go-version` and `--no-health`.

### Automatic update pull requests

The GitHub Action can optionally apply safe, mechanical updates and open or refresh one pull request. What it is allowed to change is explicit:

```yaml
permissions:
  contents: write
  pull-requests: write

steps:
  - uses: actions/checkout@<full-commit-sha>
    with:
      persist-credentials: false

  - uses: therxwold/GoSCAn@<full-commit-sha>
    env:
      GOSCAN_NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
    with:
      fail-on: high
      fail-on-outdated-go: "true"
      fail-on-unmaintained: "true"
      create-pr: "true"
      pr-vulnerabilities: "true"
      pr-go-version: "true"
      pr-toolchain: "true"
```

`pr-go-version` updates the `go` directive. `pr-toolchain` only updates an existing `toolchain` directive. `pr-vulnerabilities` applies GoSCAn's verified module fixes. Maintenance warnings such as an abandoned framework are never replaced automatically because choosing a new library is an architectural decision. The Action still returns the original scan failure after opening/updating a PR, so creating a remediation PR never hides an unresolved policy violation.

## Configuration

GoSCAn can run without a configuration file. `config.yml` is useful when you want repeatable local defaults, but CLI flags and environment variables are still first-class so CI does not need to write secrets to disk.

Configuration precedence is:

```text
built-in defaults < config.yml < environment variables < CLI flags
```

The included `config.yml` uses environment-variable placeholders for secrets:

```yaml
github:
  enabled: true
  token: "${GOSCAN_GITHUB_TOKEN}"

nvd:
  enabled: true
  api_key: "${GOSCAN_NVD_API_KEY}"

epss:
  enabled: true

ignore:
  show: false
  # GO-2026-1234:
  #   reason: "vulnerable code path is not reachable in this application"
  #   owner: "security@example.com"
  #   expires: "2026-12-31"
  # golang.org/x/net@CVE-2026-12345: "not affected on supported targets"

scan:
  fail_on: "none"
  epss_threshold: -1
  show_manifests: false
  strict_enrichment: false
  timeout: "2m"

fix:
  run_tests: true
  timeout: "5m"

output:
  format: "terminal"
```

A GitHub token is optional for public advisories, but strongly recommended for larger scans because authenticated API limits are much higher. An NVD API key is also optional but recommended to avoid the stricter public rate limit.

For local use, prefer environment variables:

```bash
export GOSCAN_GITHUB_TOKEN=github_pat_...
export GOSCAN_NVD_API_KEY=...
goscan scan
```

`GITHUB_TOKEN` and `NVD_API_KEY` are also accepted as fallback environment variable names. You can put literal token values in a private `config.yml`, but do not commit secrets to a repository.

Use another configuration file with:

```bash
goscan scan --config ./ci/goscan.yml
```

If the current project has an unrelated `config.yml`, bypass automatic config discovery while still honoring environment variables:

```bash
goscan scan --no-config
```

The GitHub Action does this automatically unless its `config:` input is explicitly set, so a repository's application configuration cannot accidentally become GoSCAn policy.

Source enrichment can be disabled independently:

```bash
goscan scan --no-github
goscan scan --no-nvd
goscan scan --no-epss
```

By default, OSV remains authoritative and optional enrichment failures are reported as warnings. For security gates that must not silently lose GitHub, NVD, or EPSS context, enable fail-closed enrichment:

```bash
goscan scan --strict-enrichment
```

When `--epss-threshold` is configured, EPSS becomes required automatically. Combining an EPSS threshold with `--no-epss` is rejected instead of allowing the policy to fail open.

The equivalent positive boolean flags, `--github` and `--nvd`, are also available and can be set explicitly with Go flag syntax such as `--github=false`. Credentials intentionally do **not** have command-line flags: keep GitHub/NVD tokens in environment variables or a private config file so they do not appear in process arguments or copied CI commands.

## Ignoring false positives

Known false positives can be suppressed in `config.yml` without deleting them from the report data. Each rule needs a reason so an exception does not quietly turn into permanent security wallpaper.

A rule can match the primary Go advisory ID or any known GHSA/CVE alias:

```yaml
ignore:
  show: false
  GO-2026-1234: "vulnerable code path is not reachable in this application"
  CVE-2026-56789:
    reason: "upstream confirmed this platform is not affected"
    owner: "security@example.com"
    expires: "2026-12-31"
```

To limit an exception to one dependency, prefix the advisory with the module path:

```yaml
ignore:
  golang.org/x/net@CVE-2026-56789: "only the unsupported target is affected"
```

Legacy string rules remain supported. Structured rules add an owner and an ISO `YYYY-MM-DD` expiration date. An expired rule no longer suppresses its finding; GoSCAn reports the finding as active and emits an expiration warning. Ignored findings are excluded from severity/EPSS CI failure decisions and from automatic fix application. JSON keeps them under `ignored_findings` with the matching rule, reason, owner, and expiration so the suppression remains auditable.

For a temporary CLI exception, `--ignore` is repeatable:

```bash
goscan scan --ignore GO-2026-1234
goscan scan --ignore 'CVE-2026-56789=confirmed false positive by upstream'
goscan scan --ignore 'golang.org/x/net@CVE-2026-56789=unsupported target only'
```

A CLI ignore without `=reason` is recorded as `ignored from CLI`. Persistent exceptions should live in `config.yml` with an explicit reason.

Ignored findings stay out of normal terminal/SARIF output. Show them when reviewing suppressions:

```bash
goscan scan --show-ignored
goscan scan --show-ignored --format=sarif
```

When included in SARIF, ignored findings use an accepted external suppression and retain the justification. JSON always retains ignored findings regardless of `--show-ignored`.

## Baseline comparison

Save the current finding set, then compare a later scan with it:

```bash
goscan scan --save-baseline .goscan-baseline.json
goscan scan --baseline .goscan-baseline.json
```

The comparison uses module path plus advisory ID as the stable identity. Existing findings are `unchanged`, severity increases are `regressed`, absent prior findings are `resolved`, and previously unseen findings are `new`. The classifications are included in terminal and JSON output; SARIF finding properties include the active classification.

## Fix planning and application

Show remediation recommendations without modifying the project:

```bash
goscan fix
```

Apply all automatically applicable first-fixed-version recommendations:

```bash
goscan fix --apply
```

Preview upgrades for every loaded dependency with a resolved newer version, plus the `go` directive and an existing `toolchain` directive:

```bash
goscan fix --latest
```

Apply that plan, using newest versions for vulnerability remediation:

```bash
goscan fix --apply --latest
```

Latest mode intentionally skips graph-only modules and replacement directives.
Go recomputes graph-only tooling versions through their loaded parents, while
replacement changes and library migrations require an explicit decision. After a successful apply and rescan, GoSCAn prints a before/after report containing selected-version changes and counts of resolved and newly introduced vulnerabilities.

The apply path is intentionally conservative:

1. Back up `go.mod` and `go.sum`.
2. Run `go get module@first-fixed` for vulnerability fixes, or `module@latest-resolved` in latest mode.
3. Run `go mod tidy`.
4. Run `go mod verify`.
5. Run `go test ./...` by default.
6. Restore `go.mod` and `go.sum` if a command, verification, or test fails.
7. Rescan after a successful apply.

Disable tests only when you explicitly want that behavior:

```bash
goscan fix --apply --test=false
```

## CI policy

Fail when a High or Critical vulnerability exists:

```bash
goscan scan --fail-on=high
```

Fail when EPSS is at least 10% even if the CVSS severity threshold does not fire:

```bash
goscan scan --fail-on=high --epss-threshold=0.10
```

Disable EPSS network enrichment when no EPSS failure threshold is configured:

```bash
goscan scan --no-epss
```

Exit codes:

- `0`: scan completed and configured policy thresholds were not exceeded.
- `1`: scan completed but a vulnerability exceeded a configured CI policy threshold, or findings remain after `fix --apply`.
- `2`: usage, dependency-resolution, network, or execution error.

## Output formats

Terminal:

```bash
goscan scan
```

JSON:

```bash
goscan scan --format=json
```

SARIF:

```bash
goscan scan --format=sarif > goscan.sarif
```

## GitHub Action

For production workflows, pin third-party actions and GoSCAn itself to reviewed full commit SHAs. GoSCAn does not require checkout credentials to remain persisted in the working tree.

```yaml
name: dependency-security

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  goscan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      # Replace <FULL_COMMIT_SHA> with a reviewed GoSCAn commit.
      - uses: therxwold/GoSCAn@<FULL_COMMIT_SHA>
        env:
          GOSCAN_NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        with:
          path: .
          fail-on: high
          epss-threshold: "0.10"
          strict-enrichment: "true"
          ignore: |
            GO-2026-1234=confirmed false positive
            golang.org/x/net@CVE-2026-56789=unsupported target only
```

The action builds GoSCAn with Go 1.26.6 and then scans `path` inside the caller workspace. GitHub Advisory enrichment uses the workflow `github.token` unless the caller explicitly provides `GOSCAN_GITHUB_TOKEN`. NVD credentials are inherited from `GOSCAN_NVD_API_KEY`; there is deliberately no secret-shaped action input or CLI token flag. Ignore rules can come from the selected `config.yml` or the newline-separated `ignore` input.

For monorepositories, set `path` to the Go module directory. To save machine-readable output instead of printing it to the workflow log:

```yaml
      - uses: therxwold/GoSCAn@<FULL_COMMIT_SHA>
        with:
          path: backend
          format: sarif
          output-file: artifacts/goscan.sarif
```

Because this repository intentionally does not publish movable release tags, a full commit SHA is the recommended production reference. `@main` is convenient for experimentation but should not be treated as an immutable security dependency.

## Other CI systems

GoSCAn is deliberately a normal CLI first, so Codeberg CI, GitLab CI, Jenkins, Woodpecker, and other runners only need the binary and a command such as:

```bash
goscan scan --fail-on=high --epss-threshold=0.10
```

## Architecture

```text
cmd/goscan
    |
    +-- dependency      selected build list + go.mod manifest audit + graph paths
    +-- config          config.yml + environment defaults
    +-- osv             OSV batch scan + advisory detail grouping
    +-- githubadvisory  GitHub reviewed advisory enrichment
    +-- nvd             NVD CVE/CVSS/CWE/KEV enrichment
    +-- cvss            CVSS 2.0/3.x/4.0 parsing and scoring
    +-- epss            FIRST EPSS enrichment
    +-- versionresolver go list module@latest
    +-- fixer           go.mod recommendations + safe apply/rollback
    +-- scanner         orchestration and policy model
    +-- output          terminal / JSON / SARIF
    +-- app             CLI wiring and application version
```

## Tests

Run the full local verification suite:

```bash
make release-check
```

The test suite is written and maintained by **Eluuna**. It is deliberately strict around the parts most likely to lie: dependency classification and graph paths, selected-parent manifest requirements, requested-vs-selected versions, local module-graph integration, OSV alias grouping/pagination/fixed-version selection, GitHub/NVD enrichment, config precedence, false-positive suppression and module scoping, EPSS parsing, CVSS 2.0/3.x/4.0 scoring, version resolution, terminal/JSON/SARIF output, CI severity/EPSS policy evaluation, and remediation planning.

Fix application tests verify the successful `go get` -> `go mod tidy` -> `go mod verify` -> `go test ./...` sequence, highest-fixed-version deduplication, optional test skipping, replacement safety, rollback on `go get`, tidy, verification, or test failure, restoration of both `go.mod` and `go.sum`, and removal of a newly created `go.sum` during rollback.

The GitHub Actions workflow also contains an `action-smoke` job that invokes the repository's own `action.yml`, writes a JSON report, and verifies the report exists. CI additionally checks `go mod tidy`, `go mod verify`, the race detector, `go vet`, `govulncheck`, and basic builds/tests on Linux, macOS, and Windows. Dependabot is configured for both Go modules and GitHub Actions.

## Release check

Before publishing a commit intended for production use:

```bash
make release-check
```

This verifies module-file tidiness and checksums, runs the race-enabled test suite and vet, builds GoSCAn, and runs `govulncheck` against GoSCAn itself. The repository CI repeats these checks with Go 1.26.6.


## Network and privacy

GoSCAn analyzes the selected module graph and project files locally, but a normal scan can contact external services. Treat module and repository names as potentially sensitive metadata, especially in corporate or private environments.

- **OSV / Go Vulnerability Database** receives selected Go module paths and versions for vulnerability matching.
- **GitHub** receives advisory identifiers for enrichment. When dependency health checks are enabled, GoSCAn also derives GitHub `owner/repository` names from module paths and queries repository metadata and, for stale repositories, the upstream README for explicit maintenance notices.
- **NVD** receives CVE identifiers when NVD enrichment is enabled. The NVD API key, when configured, is sent only as authentication to NVD.
- **FIRST EPSS** receives CVE identifiers when EPSS enrichment is enabled.
- **go.dev** is queried for the stable Go release list when Go-version health checks are enabled. That request does not include the scanned project's module graph.
- **The Go command** is used for module loading and version resolution. Operations such as `go list` and `module@latest` follow the user's Go environment, including `GOPROXY`, `GONOPROXY`, `GOPRIVATE`, and `GOSUMDB`, and may disclose requested module paths and versions to those configured services.

GoSCAn does not intentionally upload project source files, `go.mod`, `go.sum`, or environment contents to advisory services. Authentication credentials are sent only to the service they belong to and are not included in reports. Module paths, repository identifiers, and CVE/advisory identifiers can still reveal useful metadata, so organizations scanning private code should review their Go proxy/private-module settings and GoSCAn source settings before CI deployment.

Optional network sources can be reduced with `--no-github`, `--no-nvd`, `--no-epss`, `--no-health`, and `--no-go-version`. OSV remains the primary vulnerability-matching source.

## Data sources and Go semantics

GoSCAn intentionally delegates module selection to the Go command instead of reimplementing Minimal Version Selection. `go list -m -json all` is treated as the authoritative selected build list and provides each selected module's `go.mod` location and Go-version metadata. A separate read-only `go list -m -json -retracted module@version...` query adds retraction reasons without allowing a scan to rewrite the target project's `go.sum`; unavailable retraction metadata becomes a warning. GoSCAn then reads each selected manifest with `golang.org/x/mod/modfile`, the Go project's dedicated `go.mod` parser. This is intentionally separate from `go mod graph`, because Go 1.17+ module graph pruning can omit requirements that still exist in a dependency's manifest.

`go mod graph` remains the source for active ancestry. GoSCAn only accepts graph edges from the selected version of each parent module, so an older parent version that lost MVS cannot invent an active dependency path. Manifest requirements are audit/provenance data, not a second vulnerability truth source. If a dependency declares `example.com/lib v1.0.0` but MVS selects `v1.4.0`, GoSCAn scans `v1.4.0` for active vulnerabilities while retaining the `v1.0.0 -> selected v1.4.0` declaration for explanation and future fix planning.

OSV and the Go Vulnerability Database remain the primary package/version matching source. GitHub's reviewed Advisory Database is used to cross-check and enrich identified advisories, while NVD supplies CVE-centric metadata such as CVSS, CWE, references, and CISA KEV status. EPSS enrichment comes directly from FIRST and is only available when an advisory has a CVE identifier.

GitHub and NVD are enrichment sources rather than replacements for Go ecosystem matching. By default, if an enrichment service is unavailable or rate-limited, GoSCAn keeps the OSV finding and emits a warning instead of discarding the scan result. `--strict-enrichment` changes that behavior to fail closed. A configured EPSS policy threshold also makes EPSS availability mandatory.

## Current boundaries

- `govulncheck` reachability is reported as evidence and is not used to suppress dependency findings automatically.
- Automatic parent-module upgrade search is not attempted yet. For a transitive vulnerability, GoSCAn prefers the explicit minimal MVS pin because it is deterministic and directly addresses the selected vulnerable version.
- Versioned `replace` targets are scanned but not automatically rewritten.

Those boundaries are deliberate: GoSCAn focuses on getting the selected dependency graph, vulnerability matching, risk enrichment, and minimal remediation correct before adding more speculative upgrade planning.

## Credits

- **Naru K** — creator, architecture, implementation, and documentation.
- **Eluuna** — testing, documentation, and review. She tends to find the edge case everyone was sure was fine, and is usually far too pleased about it.

## License

GoSCAn is licensed under the GNU General Public License v3.0 (`GPL-3.0-only`). See [`LICENSE`](LICENSE).
