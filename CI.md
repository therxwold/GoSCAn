# CI integration

GoSCAn is a normal CLI and can run in any CI system with a supported Go
toolchain. Machine reports go to stdout; operational errors and progress go to
stderr.

## Exit codes

- `0`: the command completed and configured failure thresholds were not
  exceeded;
- `1`: the scan completed but a configured policy threshold was exceeded, or
  findings remain after `fix --apply`;
- `2`: usage, dependency-resolution, authoritative network, configuration, or
  execution error.

Optional enrichment failure is normally a warning. `--strict-enrichment` turns
enabled optional enrichment failures into exit status `2`.

## Vulnerability gates

Fail for High and Critical vulnerabilities:

```bash
goscan scan --fail-on high
```

Accepted values are `none`, `low`, `medium`, `high`, and `critical`.

Fail when EPSS probability is at least 10%, independently of the severity gate:

```bash
goscan scan --fail-on high --epss-threshold 0.10
```

An EPSS gate requires EPSS data. It cannot be combined with `--no-epss` and
fails rather than silently passing when EPSS is unavailable.

Disable EPSS enrichment when no EPSS decision is needed:

```bash
goscan scan --no-epss
```

## Health gates

```bash
goscan scan --fail-on-outdated-go
goscan scan --fail-on-unmaintained
```

The first gate covers an outdated `go` directive or existing `toolchain`
directive according to the current command contract. The second covers explicit
unmaintained or archived evidence. Stale and merely outdated dependencies remain
reported health signals rather than vulnerability failures.

## Baselines in CI

```bash
goscan scan --baseline .goscan-baseline.json --format json > goscan.json
```

JSON identifies findings as new, unchanged, regressed, or resolved. Dedicated
baseline-only failure switches are not yet implemented. A pipeline that gates
only new or regressed findings must inspect those JSON classifications.

## JSON artifacts

```bash
goscan scan --format json > goscan.json
```

JSON includes `schema_version: 1`. Archive the report with:

- the target repository commit;
- GoSCAn version and pinned revision;
- effective non-secret configuration;
- Go version and build environment;
- selected local vulnerability database metadata, when used.

Do not decide that a zero finding count is complete without checking warnings,
`package_analysis`, enabled sources, and integrity status.

## SARIF artifacts

```bash
goscan scan --format sarif > goscan.sarif
```

SARIF 2.1.0 results can be uploaded to compatible code-scanning platforms.
Ignored findings remain absent unless `--show-ignored` is supplied, in which case
they carry accepted external suppressions.

When redirecting a machine format, do not merge stderr into the output file.

Optional Zerolog diagnostics also use stderr. Enable newline-delimited JSON logs
without contaminating a JSON report:

```bash
GOSCAN_LOG_LEVEL=info GOSCAN_LOG_FORMAT=json \
  goscan scan --format json > goscan.json 2> goscan.log.jsonl
```

## Read-only GitHub Action

Pin both checkout and GoSCAn to reviewed full commit SHAs:

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
      - uses: actions/checkout@<FULL_COMMIT_SHA>
        with:
          persist-credentials: false

      - uses: therxwold/GoSCAn@<FULL_COMMIT_SHA>
        env:
          GOSCAN_NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        with:
          path: .
          fail-on: high
          epss-threshold: "0.10"
          strict-enrichment: "true"
          log-level: info
          log-format: json
          ignore: |
            GO-2026-1234=confirmed false positive
            golang.org/x/net@CVE-2026-56789=unsupported target only
```

The Action:

- builds GoSCAn with Go 1.27;
- scans `path` inside the caller workspace;
- uses `github.token` for GitHub enrichment unless
  `GOSCAN_GITHUB_TOKEN` is explicitly supplied;
- inherits `GOSCAN_NVD_API_KEY` without exposing a secret-shaped Action input;
- uses `--no-config` unless `config:` is set explicitly;
- validates repository-relative `path`, `config`, and `output-file` inputs.

Save an artifact to a repository-relative path:

```yaml
      - uses: therxwold/GoSCAn@<FULL_COMMIT_SHA>
        with:
          path: backend
          format: sarif
          output-file: artifacts/goscan.sarif
```

The workflow should upload that file in a later step appropriate to the CI
platform.

## Automated remediation Action

Use a separate trusted default-branch workflow or job with write permissions:

```yaml
permissions:
  contents: write
  pull-requests: write

steps:
  - uses: actions/checkout@<FULL_COMMIT_SHA>
    with:
      persist-credentials: false

  - uses: therxwold/GoSCAn@<FULL_COMMIT_SHA>
    with:
      path: .
      fail-on: high
      fail-on-outdated-go: "true"
      fail-on-unmaintained: "true"
      create-pr: "true"
      pr-vulnerabilities: "true"
      pr-go-version: "true"
      pr-toolchain: "true"
```

The composite Action cannot grant permissions itself. The calling workflow owns
the permission boundary.

PR generation occurs only when:

- `create-pr` is true;
- the event is not a pull-request event;
- the current ref is the repository default branch.

The Action preserves scan-affecting provider, health, strict, and ignore settings
during remediation. It accepts a partial remediation status so useful changes
can still be proposed, then enforces the original scan result.

Run mutation only on trusted code. Tests and Go commands execute with the job's
permissions.

## Monorepositories and workspaces

Create one matrix entry per Go module and disable ambient workspace state:

```yaml
strategy:
  matrix:
    module:
      - services/api
      - services/worker
      - libraries/shared

steps:
  - run: GOWORK=off goscan scan --format json "${{ matrix.module }}"
```

GoSCAn rejects an active `go.work` rather than combining several main modules
into a misleading report.

## Other CI systems

GitLab CI, Jenkins, Woodpecker, Codeberg CI, and similar systems need only the
binary and an ordinary command:

```bash
goscan scan --fail-on high --epss-threshold 0.10
```

Apply the same controls regardless of platform:

- pin the GoSCAn artifact or source revision;
- keep scan jobs read-only;
- separate remediation credentials;
- retain JSON/SARIF and stderr diagnostics;
- cap job duration above GoSCAn's own timeout;
- configure private module proxy and checksum behavior;
- scan each module independently.

## Publishing releases

The source version in `internal/app/app.go` must match the pushed Git tag. Build
the release assets locally with:

```bash
make release-check
make release-dist
```

Assets are written under `dist/<version>/`:

```text
goscan-vX.Y.Z-linux-amd64.tar.gz
goscan-vX.Y.Z-darwin-arm64.tar.gz
goscan-vX.Y.Z-windows-amd64.zip
SHA256SUMS
```

Every archive contains the platform binary, license, example configuration, and
public user documentation.

Pushing a `v*` tag triggers `.github/workflows/release.yml`. The workflow:

1. runs the complete release gate;
2. rejects a tag that differs from the source version;
3. cross-compiles and packages all three targets;
4. creates the GitHub Release with generated notes;
5. uploads the archives and SHA-256 checksum file.

Recommended release commands are:

```bash
git tag -s vX.Y.Z -m "GoSCAn vX.Y.Z"
git push origin vX.Y.Z
```

Use the current source version rather than copying the example version literally.

## Reproducibility checklist

- [ ] Pin GoSCAn and third-party CI actions.
- [ ] Record the target commit and Go toolchain.
- [ ] Preserve the report schema version.
- [ ] Retain warnings and incomplete-analysis status.
- [ ] Supply provider credentials from the CI secret store.
- [ ] Set `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, and proxy settings correctly.
- [ ] Use `GOWORK=off` for independent module-matrix scans.
- [ ] Restrict write permissions to remediation jobs.
- [ ] Review `go.mod`, `go.sum`, tests, and before/after results before merging.
