# GoSCAn specifications

This document defines the user-visible scanning model, terminology, data-source
roles, and machine-readable contracts. Command examples assume execution inside
one Go module unless a path is supplied.

## Selected dependency model

GoSCAn delegates module selection to the Go command. The selected build list from
`go list -m -json all` is authoritative; GoSCAn does not infer active versions by
reading `require` directives alone.

Dependencies are classified as:

- `direct`: explicitly required by the main `go.mod` without `// indirect`;
- `indirect`: explicitly required by the main `go.mod` with `// indirect`;
- `transitive`: selected through another module and not explicitly required by
  the main module.

The requested version and selected version are separate facts. For example, a
dependency can request `example.com/lib v1.0.0` while MVS selects `v1.4.0`.
GoSCAn scans `v1.4.0` and retains `v1.0.0 -> selected v1.4.0` only as provenance.

`go mod graph` supplies active ancestry paths. Only edges from the selected
version of a parent are accepted, preventing a parent version that lost MVS from
inventing an active path. Malformed graph records produce a warning; the
separately loaded selected build list remains scannable.

## Manifest audit

GoSCAn parses the root and available selected dependency `go.mod` files with
`golang.org/x/mod/modfile`. JSON always includes manifest metadata. Display it in
terminal output with:

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

A manifest that cannot be inspected is reported as unavailable. Missing
manifest data does not create an extra active dependency.

## Package scope

GoSCAn loads `./...` twice: once for production packages and once with tests.
Selected modules are scoped as:

- `runtime`: at least one package is loaded outside tests;
- `test-only`: packages are loaded only while tests are included;
- `graph-only`: the module is selected but no package is mapped to it in the
  successfully analyzed build context.

The active `GOOS`, `GOARCH`, build tags, module mode, and Go environment affect
package loading. Platform-specific or tag-specific code requires scans under
each relevant environment.

When package loading is incomplete, the report sets `package_analysis` to false,
emits a warning, and retains conservative module-level vulnerability matches.
Missing package evidence is never treated as proof of safety.

## Vulnerability matching

For every selected scannable module, GoSCAn sends its module path and selected
version to OSV using the Go ecosystem.

OSV records are normalized as follows:

- GO, GHSA, CVE, and other connected aliases are grouped into one finding;
- affected ranges are evaluated against the selected version;
- the first fixed version closing the active affected interval is retained;
- Go ecosystem import and symbol metadata is preserved;
- package metadata filters findings only when package analysis completed;
- severity and references retain source provenance.

OSV is authoritative for finding identity. GitHub, NVD, and EPSS enrich existing
findings; they do not independently create or erase an OSV finding.

## Reachability

GoSCAn runs the official `govulncheck` analyzer over application and test
packages. Evidence can progress through these levels:

- module selected;
- affected package loaded;
- vulnerable symbol present;
- vulnerable symbol called, with a source-to-sink call path when available.

Reachability is evidence, not automatic suppression. A module finding remains
visible when a call path is absent, particularly when package analysis or
reachability analysis is incomplete.

Disable reachability analysis with:

```bash
goscan scan --no-reachability
```

Select a compatible local or remote Go vulnerability database with:

```bash
goscan scan --vulndb /var/cache/goscan/vulndb
GOSCAN_VULNDB=file:///var/cache/goscan/vulndb goscan scan
```

## Replacements

Replacement handling follows the code actually selected:

- Local filesystem replacements are not matched to registry advisories because
  a registry version no longer identifies their contents.
- Versioned replacements are scanned using the replacement module path and
  version.
- Automatic remediation does not rewrite replacement directives because the
  intended fork or replacement scope cannot be inferred safely.

## Retractions and integrity

GoSCAn queries retraction metadata for exact selected versions without allowing
that query to rewrite the target module. Retraction lookup failure is a warning;
known retraction reasons remain distinct from vulnerabilities.

`go mod verify` checks downloaded module content. Reports distinguish successful
verification, a missing `go.sum`, and verification failure.

## Go and dependency health

Health findings are separate from vulnerability findings.

The Go release check queries the official Go download metadata, filters stable
releases, and selects the highest toolchain using Go semantic-version rules. It
compares:

- the main module's `go` directive with the newest language release line;
- an existing `toolchain` directive with the newest stable toolchain.

The `go` directive describes minimum language and module semantics. It does not
prove which toolchain currently runs the application.

Dependency health can report:

- `OUTDATED`: a newer selected-module release exists;
- `DEPRECATED`: module metadata points to a replacement or deprecation notice;
- `RETRACTED`: the selected version is retracted;
- `ARCHIVED`: the mapped GitHub repository is archived;
- `STALE`: no recent repository push was observed within the configured window;
- `UNMAINTAINED`: repository metadata or upstream documentation explicitly says
  the project is unmaintained.

Health checks include direct, indirect, and transitive selected modules. Disable
them with `--no-health` or disable only Go release checks with `--no-go-version`.

## Data-source roles

| Source | Role | Failure behavior |
| --- | --- | --- |
| OSV | Authoritative module/version vulnerability matching | Scan error |
| Go vulnerability database / `govulncheck` | Package, symbol, and call-path evidence | Warning normally; error in strict mode |
| GitHub Advisory Database | Reviewed advisory and CVSS enrichment | Warning normally; error in strict mode |
| NVD | CVE, CVSS, CWE, references, and CISA KEV enrichment | Warning normally; error in strict mode |
| FIRST EPSS | Exploit probability and percentile | Warning normally; required when an EPSS gate is configured |
| GitHub repositories | Archive, activity, and maintenance metadata | Warning normally; required by maintained-dependency policy |
| Go downloads metadata | Current stable Go release | Warning normally; required by current-Go policy |
| Go proxy and checksum database | Module loading and latest-version resolution | Governed by the requested scan stage and Go environment |

`--strict-enrichment` changes enabled optional enrichment failures into scan
errors. It does not change OSV's authoritative role.

## Output contracts

### Terminal

Terminal output is intended for developers. It includes summary counts,
dependency paths, evidence, remediation context, health signals, integrity, and
warnings.

### JSON

```bash
goscan scan --format json
```

JSON reports include `schema_version: 1`. Consumers should check this value and
reject unsupported future contracts explicitly. Findings, aliases, dependency
paths, health records, warnings, and remediation data are ordered
deterministically.

### SARIF

```bash
goscan scan --format sarif > goscan.sarif
```

GoSCAn emits SARIF 2.1.0 with stable rule ordering, repository-root-relative
`go.mod` fallback locations, finding properties, and accepted external
suppressions for ignored findings when requested.

## Baseline contract

New baseline files use version 2. Version 1 remains readable. Identity is based
on module path plus overlap among the primary and alias advisory identifiers,
preventing a GO/GHSA/CVE canonical-ID change from appearing as a false
new/resolved pair.

Baseline classifications are:

- `new`;
- `unchanged`;
- `regressed` when normalized severity increased;
- `resolved` when no matching current finding exists.

## Workspace boundary

One Go module is scanned per invocation. Active `go.work` files are rejected
because workspace main modules and workspace replacements cannot be represented
truthfully in a single-module report.

Scan modules independently:

```bash
GOWORK=off goscan scan ./services/api
GOWORK=off goscan scan ./services/worker
```

Aggregate workspace reporting is not currently implemented.

## Current non-goals

- A missing call path does not automatically suppress a finding.
- The local Go vulnerability database does not make the complete scan offline.
- Parent-aware transitive upgrade discovery is not automatic.
- Replacement directives are not rewritten automatically.
- Several modules are not aggregated into one report.
- General policy-as-code is not part of the current product contract.
