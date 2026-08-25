# Security and privacy

GoSCAn analyzes project and dependency metadata locally, but a normal scan can
contact external services. Module paths, versions, repository names, and
advisory identifiers can be sensitive even when source code is not uploaded.

## Network egress

| Destination | Data sent | Control |
| --- | --- | --- |
| OSV | Selected module paths and versions | Primary online matcher; fully local matching is not implemented |
| GitHub API | GHSA/CVE IDs; GitHub repository names for health checks | `--no-github`, `--no-health`, token scope |
| NVD | CVE IDs | `--no-nvd` |
| FIRST EPSS | CVE IDs | `--no-epss` |
| Go downloads service | Stable-release metadata request without the project graph | `--no-go-version` |
| Configured Go proxy/checksum DB | Module paths and versions requested by Go tooling | Go environment settings |

Go commands follow:

- `GOPROXY` and `GONOPROXY`;
- `GOPRIVATE`;
- `GOSUMDB` and `GONOSUMDB`;
- proxy credentials and transport settings configured outside GoSCAn.

GoSCAn does not intentionally send project source files, `go.mod`, `go.sum`, or
the complete process environment to advisory providers. Provider requests can
still disclose internal dependency and repository names.

## Reducing network access

Disable optional sources:

```bash
goscan scan \
  --no-github \
  --no-nvd \
  --no-epss \
  --no-health \
  --no-go-version .
```

OSV still receives selected module paths and versions. Module loading and
latest-version resolution can contact the configured Go proxy.

`goscan db update` installs a local database for `govulncheck` reachability:

```bash
goscan db update
goscan scan --vulndb /var/cache/goscan/vulndb
```

This does not make the authoritative OSV query or enabled enrichment providers
offline.

## Credentials

Use environment variables or a CI secret store:

```bash
export GOSCAN_GITHUB_TOKEN=...
export GOSCAN_NVD_API_KEY=...
```

Avoid literal credentials in committed configuration. GoSCAn removes user-info,
query parameters, and fragments before persisting or displaying a vulnerability
database source URL.

Recommended controls:

- use a read-only GitHub token for scans;
- use separate short-lived write credentials for remediation PR jobs;
- do not expose write tokens to untrusted fork workflows;
- avoid shell tracing during credential setup;
- do not copy tokens into CLI arguments;
- review proxy credentials independently from provider credentials.

## Provider failure model

OSV is authoritative. If it fails, the scan cannot claim a complete
vulnerability result and returns an error.

GitHub, NVD, EPSS, repository health, Go release metadata, and reachability are
enrichment or evidence stages. They normally produce visible warnings while
retaining OSV findings. Use:

```bash
goscan scan --strict-enrichment
```

when every enabled source is required. An EPSS policy threshold also requires
EPSS automatically.

Package-loading failure is handled conservatively: package filtering is disabled
and module-level findings remain. Always inspect report warnings and
`package_analysis` before interpreting a low finding count.

## Untrusted repositories

An ordinary scan runs Go tooling over the checkout and can download modules or
toolchains. It does not run `go generate` or application tests, but source
analysis should still run inside a disposable worker with normal CI isolation.

`fix --apply` is a stronger trust boundary. Depending on options it runs:

- `go get`;
- `go mod tidy`;
- `go mod verify`;
- `go test ./...`;
- another complete scan.

Repository-controlled tests and build steps execute with the job's permissions.
Do not run automated remediation against untrusted pull requests, forks, or
checkouts on privileged shared runners.

## Remediation recovery boundary

GoSCAn restores `go.mod` and `go.sum` after ordinary reported failures. This
does not protect against:

- process or machine termination;
- disk and filesystem failure;
- concurrent modification;
- arbitrary changes made by repository-controlled test code;
- failures that prevent cleanup from running.

Use a clean checkout or temporary worktree so the entire job can be discarded.
Review all module changes because Go MVS and `go mod tidy` can update related
requirements and checksums.

## Vulnerability database integrity

Downloaded database ZIP files are treated as untrusted:

- compressed and extracted sizes are bounded;
- absolute and traversal paths are rejected;
- non-regular or unexpected entries are rejected;
- required indexes and advisory JSON are validated;
- installation is staged and replaced only after validation;
- a prior valid database is preserved when download or validation fails;
- source URL, upstream modification time, download time, and advisory count are
  recorded in `.goscan.json`.

Database age and successful installation do not prove that every external
provider is current or available.

## GitHub Actions permissions

The composite Action cannot grant workflow permissions. A read-only scan should
normally use:

```yaml
permissions:
  contents: read
```

Only the trusted remediation job should use:

```yaml
permissions:
  contents: write
  pull-requests: write
```

Automatic PR generation is restricted to the repository default branch and is
disabled for pull-request events.

## Enterprise evidence and retention

Retain these together for audit and incident review:

- GoSCAn version and pinned source/artifact revision;
- target repository commit;
- JSON or SARIF report, including warnings;
- effective non-secret configuration and provider selection;
- Go version, build context, and workspace state;
- relevant private-module proxy settings with secrets redacted;
- local vulnerability database metadata;
- baseline and exception revision;
- remediation before/after report and test status.

Do not equate exit status `0` with universal safety. It means the configured
checks completed without crossing their current thresholds under the analyzed
build context.

Release downloads include `SHA256SUMS`. After downloading all four release
assets into one directory, verify the archives before extraction:

```bash
sha256sum --check SHA256SUMS
```

On systems without `sha256sum`, use the platform's SHA-256 verification tool and
compare it with the corresponding entry.

## Workspace and build-context coverage

GoSCAn analyzes the active `GOOS`, `GOARCH`, build tags, and packages below
`./...`, including tests. Run separate scans for every supported build context
whose dependency or reachability evidence matters.

Active `go.work` files are rejected to prevent multiple main modules and
workspace replacements from being collapsed. Use independent module scans:

```bash
GOWORK=off goscan scan ./services/api
GOWORK=off goscan scan ./services/worker
```

## Reporting security issues

When reporting a suspected security issue, include the GoSCAn version, minimal
reproduction, target Go version, relevant non-secret configuration, and whether
the issue affects scanning, reporting, or mutation. Do not include live tokens,
private module names, or proprietary source unless a private reporting channel
has been agreed with the maintainers.

## License considerations

GoSCAn is GPL-3.0-only. Internal execution does not by itself distribute the
program outside an organization. Distribution of binaries or derivative versions
can create source, notice, and license obligations. GPLv3 is not the Affero GPL;
network use alone does not create AGPL-style source disclosure requirements.

Whether a combined or embedded product is a derivative work depends on its
actual architecture. Organizations distributing or embedding GoSCAn should
obtain advice for their concrete distribution model.
