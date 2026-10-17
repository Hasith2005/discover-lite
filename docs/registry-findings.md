# Findings: the official MCP Registry

## What was scanned

- **Date fetched:** 17 October 2026
- **Source:** `https://registry.modelcontextprotocol.io/v0/servers?limit=100`, following `metadata.nextCursor` to the end
- **Size:** 1,570 pages and 156,918 entries. The registry lists every published version of a server, so only the latest version of each was kept (`_meta."io.modelcontextprotocol.registry/official".isLatest`). That leaves **45,372 servers**.
- **How entries are read:** each registry package is turned into the command an MCP client would run (an npm package becomes `npx pkg@version`, a PyPI package becomes `uvx pkg==version`). The same `unpinned_package` rule that judges real client configs then judges the registry, so the two sets of numbers are directly comparable.

To reproduce: `discover-lite fetch-registry`, then `discover-lite stats data/registry/`.

## Statistics

| Measure | Count | Share |
|---|---|---|
| Servers (latest version of each) | 45,372 | |
| Servers with a package (run locally over stdio) | 17,756 | 39.1% |
| Servers with a remote endpoint | 29,269 | 64.5% |
| Servers with both | 2,161 | 4.8% |
| Servers with an unpinned package | 12 | <0.1% |
| Servers with a plain-HTTP remote (non-local) | 0 | 0.0% |
| Servers declaring at least one secret environment variable | 6,657 | 14.7% |
| Packages | 19,307 | |
| Packages run with a package runner (npx, uvx, bunx, pnpx) | 15,695 | 81.3% of packages |
| Package-runner packages with no exact version | 22 | 0.1% |
| Package-runner packages set to `latest` | 15 | 0.1% |

Packages by registry: npm 11,644 (60.3%), PyPI 4,539 (23.5%), MCPB 1,710 (8.9%), OCI images 1,172 (6.1%), NuGet 155 (0.8%), Cargo 87 (0.5%).

Findings by check: `unpinned_package` (medium) fired 22 times on 12 servers. No other check fired.

## Comparison with real client configs

The same rules, run on 391 public client configs from GitHub (see `docs/github-findings.md`):

| Measure | Registry (publishers) | GitHub configs (users) |
|---|---|---|
| Package-runner servers with no exact version | 0.1% | 91.1% |
| Package-runner servers set to `latest` | 0.1% | 29.2% |
| Remote servers on plain HTTP | 0.0% | 1.0% |
| Hard-coded secrets | none found | 5.1% of configs |

## Three takeaways

1. **Publishers pin; users do not.** Almost every package in the registry names an exact version, but 91% of servers in real client configs run with no version at all. The version information is lost between publication and use, most likely because setup guides tell people to write `npx -y package` (this cause is a reasonable guess, not something the data shows). The supply-chain risk sits in the client config, not in the registry.
2. **The registry follows good secret practice.** 14.7% of servers declare a secret environment variable, which is the correct way for a server to ask for a credential, and no registry entry contains a hard-coded secret. This is recorded as a statistic, not a finding.
3. **Remote MCP has arrived.** 64.5% of registry servers offer a remote endpoint, and every remote endpoint uses HTTPS. For remote servers, the questions that matter move from packages to authentication and data handling, which the registry does not describe.

## Corrections made while analysing this data

The first run over the registry exposed three problems in the scanner. Each was fixed and covered by a test before the numbers above were produced.

- **False secrets inside words.** The `sk-` key pattern matched inside package names such as `breakerdesk-electrician-tools` and `task-graph-mcp`, giving 7 false hits. Every key format now has to start at a word boundary. This change did not alter the GitHub results.
- **Exact Python versions counted as unpinned.** Pre-release and development versions such as `0.1.0a4`, `0.1.0rc2` and `3.0.0.dev1` are exact versions, but the first rule did not accept them. The rule now follows Python's version format (PEP 440). Unpinned packages fell from 61 to 22.
- **A misleading count.** 66 pages contained only old versions and so produced no servers. They were first reported as "not recognised"; the label now says what they are.

## Limitations

- **The registry describes how servers are published and installed, not how any organisation has configured them.** A pinned version in the registry says nothing about what a user actually runs.
- **The registry does not list tools**, so tool checks such as `no_human_in_loop` cannot apply.
- **Authentication details are not recorded**, so the missing-Authorization part of `insecure_remote_server` is skipped for registry entries. A missing header here means "the registry does not say".
- **Package types outside npm and PyPI** (MCPB, OCI, NuGet, Cargo) are counted but not judged for pinning. In particular, Docker image tags and digests are not yet checked.
- **Publication is not vetting.** A server being listed in the registry does not mean its code has been reviewed.
