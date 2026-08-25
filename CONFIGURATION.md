# Configuration

GoSCAn works without a configuration file. Use `config.yml` for repeatable local
defaults and environment variables for secrets.

## Precedence

Effective configuration is assembled in this order:

```text
built-in defaults < config.yml < credential environment variables < CLI flags
```

The YAML decoder is strict. Unknown fields and multiple YAML documents return an
error instead of being silently ignored.

Use a specific file with:

```bash
goscan scan --config ./ci/goscan.yml
```

Disable automatic `config.yml` discovery while retaining environment
credentials:

```bash
goscan scan --no-config
```

The GitHub Action uses `--no-config` unless its `config` input is set explicitly.

## Complete example

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
  #   reason: "vulnerable code path is not reachable"
  #   owner: "security@example.com"
  #   expires: "2026-12-31"
  # golang.org/x/net@CVE-2026-12345: "unsupported target only"

health:
  enabled: true
  check_go: true
  stale_after_days: 730
  fail_on_outdated_go: false
  fail_on_unmaintained: false

scan:
  fail_on: "none"
  epss_threshold: -1
  show_manifests: false
  strict_enrichment: false
  timeout: "2m"

fix:
  run_tests: true
  vulnerabilities: true
  upgrade_go: false
  upgrade_toolchain: false
  timeout: "5m"

output:
  format: "terminal"
```

The repository's `config.yml` is the maintained example for the exact current
schema.

## Credentials

Preferred environment variables:

```bash
export GOSCAN_GITHUB_TOKEN=github_pat_...
export GOSCAN_NVD_API_KEY=...
goscan scan
```

Accepted names are:

| Provider | Preferred | Fallback |
| --- | --- | --- |
| GitHub | `GOSCAN_GITHUB_TOKEN` | `GITHUB_TOKEN` |
| NVD | `GOSCAN_NVD_API_KEY` | `NVD_API_KEY` |

Credentials intentionally have no CLI flags so they do not appear in process
arguments or copied command histories. Literal credentials can be placed in a
private configuration file, but must never be committed.

Environment placeholders are expanded in credential and ignore metadata fields.
An unset placeholder becomes an empty value.

## Provider selection

Disable optional providers independently:

```bash
goscan scan --no-github
goscan scan --no-nvd
goscan scan --no-epss
goscan scan --no-health
goscan scan --no-go-version
goscan scan --no-reachability
```

Equivalent positive GitHub and NVD flags accept standard Go boolean syntax:

```bash
goscan scan --github=false --nvd=true
```

OSV remains the authoritative online vulnerability matcher and cannot currently
be disabled in favor of a fully local matcher.

By default, optional enrichment failures become warnings. Fail closed for every
enabled enrichment source with:

```bash
goscan scan --strict-enrichment
```

An EPSS threshold automatically makes EPSS required. Combining an active EPSS
threshold with `--no-epss` is rejected.

## Timeouts

The scan and fix commands have independent overall timeouts:

```yaml
scan:
  timeout: "2m"
fix:
  timeout: "5m"
```

Override them per invocation:

```bash
goscan scan --timeout 3m
goscan fix --timeout 10m
```

Timeouts must be positive. Built-in HTTP clients also have request-level default
timeouts; the overall context remains the upper bound for the complete command.

## Health settings

```yaml
health:
  enabled: true
  check_go: true
  stale_after_days: 730
  fail_on_outdated_go: false
  fail_on_unmaintained: false
```

CLI equivalents include:

```bash
goscan scan --stale-after-days 730
goscan scan --fail-on-outdated-go
goscan scan --fail-on-unmaintained
```

`stale_after_days` must be greater than zero. A stale repository is a maintenance
signal, not a known vulnerability.

## Ignore rules

Every persistent exception requires a reason. Rules match a primary advisory ID
or any known GO/GHSA/CVE alias.

```yaml
ignore:
  show: false
  GO-2026-1234: "upstream confirmed the application is unaffected"
  CVE-2026-56789:
    reason: "unsupported platform only"
    owner: "security@example.com"
    expires: "2026-12-31"
```

Limit an exception to one module by prefixing the identifier:

```yaml
ignore:
  golang.org/x/net@CVE-2026-56789:
    reason: "affected package is excluded from supported builds"
    owner: "networking-team@example.com"
    expires: "2026-10-01"
```

Expiration uses ISO `YYYY-MM-DD`. An expired rule no longer suppresses the
finding and produces a warning.

Temporary CLI exceptions are repeatable:

```bash
goscan scan --ignore GO-2026-1234
goscan scan --ignore 'CVE-2026-56789=confirmed false positive'
goscan scan --ignore 'golang.org/x/net@CVE-2026-56789=unsupported target'
```

A CLI rule without `=reason` records `ignored from CLI` as its reason.

Ignored findings:

- do not trigger severity or EPSS failure decisions;
- are excluded from automatic remediation;
- remain in JSON under `ignored_findings` with audit metadata;
- are hidden from terminal and SARIF output unless `--show-ignored` is used;
- use an accepted external SARIF suppression when shown.

Review suppressions with:

```bash
goscan scan --show-ignored
goscan scan --show-ignored --format sarif
```

## Baselines

Save the current active and ignored finding identity:

```bash
goscan scan --save-baseline .goscan-baseline.json
```

Compare a later scan:

```bash
goscan scan --baseline .goscan-baseline.json
```

Findings become `new`, `unchanged`, `regressed`, or `resolved`. Baseline v2
stores aliases so a canonical identifier change between GO, GHSA, and CVE does
not produce a false new/resolved pair. Baseline v1 remains readable.

Baseline classification is report data. Dedicated `--fail-on-new` and
`--fail-on-regressed` switches are not currently implemented.

## Local vulnerability database selection

Install the official snapshot at the default cache path:

```bash
goscan db update
```

Choose a custom installation path or source:

```bash
goscan db update --path /var/cache/goscan/vulndb
goscan db update --url https://security.example.com/vulndb.zip
```

Select it explicitly for reachability:

```bash
goscan scan --vulndb /var/cache/goscan/vulndb
GOSCAN_VULNDB=file:///var/cache/goscan/vulndb goscan scan
```

The database currently supplies `govulncheck`, not the primary OSV module query.

## Discovering the exact CLI

The executable help is authoritative for flags and defaults:

```bash
goscan --help
goscan scan --help
goscan fix --help
goscan db --help
```
