# GoSCAn

GoSCAn is a Go dependency vulnerability scanner and remediation planner. It scans the complete module build list selected by Go MVS, including direct requirements, explicit `// indirect` requirements, and deeper transitive modules.

Its job is not only to say that a dependency is vulnerable. It also explains why that dependency is in the graph, finds the first fixed version, resolves the current latest version, enriches CVEs with EPSS exploitation probability, and proposes the smallest useful `go.mod` repair.

## What it does

- Scans **every versioned module selected by `go list -m -json all`**.
- Classifies modules as `direct`, `indirect`, or `transitive` for reporting.
- Builds dependency paths from `go mod graph`.
- Queries OSV using the Go ecosystem and the exact selected module version.
- Groups duplicate OSV/GO/GHSA/CVE aliases into one finding.
- Extracts the first fixed version that closes the vulnerable range containing the selected version.
- Resolves `@latest` for vulnerable modules.
- Parses and calculates CVSS 2.0, 3.0, 3.1, and 4.0 scores with `github.com/pandatix/go-cvss`.
- Fetches FIRST EPSS score and percentile for CVEs.
- Recommends an explicit `// indirect` `go.mod` requirement for vulnerable transitive dependencies when there is a fixed version.
- Supports terminal, JSON, and SARIF output.
- Supports CI policy exits by severity and/or EPSS threshold.
- Can apply fixes with `go get`, run `go mod tidy`, run tests, and roll back `go.mod`/`go.sum` if verification fails.

Local filesystem replacements are intentionally skipped because a registry version no longer identifies the code being built. Versioned `replace` targets are scanned, but GoSCAn does not automatically rewrite replacement directives in v0.1 because guessing the intended replacement scope is unsafe.

## Requirements

GoSCAn requires **Go 1.26 or newer**. The module declares `toolchain go1.26.6`, so development and release builds prefer Go 1.26.6 when Go toolchain switching is available.

GoSCAn intentionally keeps its third-party dependency set small, but it does not reimplement mature parsers or standards logic:

- `go.yaml.in/yaml/v3` parses `config.yml`.
- `golang.org/x/mod` handles `go.mod` parsing and Go semantic-version comparison.
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
goscan v0.1.0
```

## Scan

Run in a Go module:

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
  Fixed:    v0.25.0
  Latest:   v0.44.0
  CVSS:     8.1 (3.1)
  EPSS:     72.40% (percentile 98.10%)
  Path:
    example.com/app
    └── github.com/example/parent@v1.8.0
    └── golang.org/x/net@v0.20.0
  Fix:      go get golang.org/x/net@v0.25.0
  go.mod recommendation:
    + require golang.org/x/net v0.25.0 // indirect
```

The explicit transitive pin works with Go MVS by raising the minimum selected version in the main module. GoSCAn recommends the **first fixed version**, not `@latest`, as the minimal security repair. The latest version is shown separately so the developer can choose a larger upgrade deliberately.

## Fix planning and application

Show remediation recommendations without modifying the project:

```bash
goscan fix
```

Apply all automatically applicable first-fixed-version recommendations:

```bash
goscan fix --apply
```

The apply path is intentionally conservative:

1. Back up `go.mod` and `go.sum`.
2. Run `go get module@first-fixed` for each affected module.
3. Run `go mod tidy`.
4. Run `go test ./...` by default.
5. Restore `go.mod` and `go.sum` if a command or test fails.
6. Rescan after a successful apply.

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

Disable EPSS network enrichment:

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

GitHub Action usage:

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
    steps:
      - uses: actions/checkout@v5
      - uses: therxwold/GoSCAn@main
        with:
          fail-on: high
          epss-threshold: "0.10"
```

The action builds GoSCAn using the Go version declared by GoSCAn itself, then scans the caller workspace. This avoids making the scanner build depend on whether the target project uses an older Go release.

## Other CI systems

GoSCAn is deliberately a normal CLI first, so Codeberg CI, GitLab CI, Jenkins, Woodpecker, and other runners only need the binary and a command such as:

```bash
goscan scan --fail-on=high --epss-threshold=0.10
```

## Architecture

```text
cmd/goscan
    |
    +-- dependency      go env / go list / go mod graph
    +-- osv             OSV batch scan + advisory detail grouping
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
go test -race ./...
go vet ./...
make build
```

The test suite is written and maintained by **Eluuna**. It is deliberately strict around the parts most likely to lie: dependency classification and graph paths, local module-graph integration, OSV alias grouping/pagination/fixed-version selection, EPSS parsing, CVSS 2.0/3.x/4.0 scoring, version resolution, terminal/JSON/SARIF output, CI severity/EPSS policy evaluation, and remediation planning.

Fix application tests verify the successful `go get` -> `go mod tidy` -> `go test ./...` sequence, highest-fixed-version deduplication, optional test skipping, replacement safety, rollback on `go get` failure, rollback on `go mod tidy` failure, rollback on test failure, restoration of both `go.mod` and `go.sum`, and removal of a newly created `go.sum` during rollback.

The GitHub Actions workflow also contains an `action-smoke` job that invokes the repository's own `action.yml`, so the composite action path is exercised end to end in CI rather than only compiling the CLI directly.

## Data sources and Go semantics

GoSCAn intentionally delegates module selection to the Go command instead of reimplementing Minimal Version Selection. `go list -m -json all` is treated as the authoritative selected build list and `go mod graph` is used to explain dependency ancestry.

Vulnerability data comes from OSV using the `Go` ecosystem. EPSS enrichment comes from FIRST and is only available when an advisory has a CVE identifier.

## Current v0.1 boundaries

- Source-level vulnerable-symbol reachability is not used to suppress dependency findings. GoSCAn intentionally reports vulnerable selected modules even when the vulnerable symbol may not be reachable, because its primary job is dependency hygiene and remediation.
- Automatic parent-module upgrade search is not attempted yet. For a transitive vulnerability, v0.1 prefers the explicit minimal MVS pin because it is deterministic and directly addresses the selected vulnerable version.
- Versioned `replace` targets are scanned but not automatically rewritten.

Those boundaries are deliberate: v0.1 focuses on getting the selected dependency graph, vulnerability matching, risk enrichment, and minimal remediation correct before adding more speculative upgrade planning.

## License

GoSCAn is licensed under the GNU General Public License v3.0 (`GPL-3.0-only`). See [`LICENSE`](LICENSE).
