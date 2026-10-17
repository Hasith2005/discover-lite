# Findings: public MCP client configs on GitHub

## What was scanned

- **Date fetched:** 17 October 2026
- **Source:** GitHub code search API, query `mcpServers filename:<name>`, in GitHub's best-match order
- **File names:** `.mcp.json` (Claude Code) and `claude_desktop_config.json` (Claude Desktop), 200 of each
- **Filtering:** exact file names only. Paths that look like documentation (example, sample, template, demo, docs, tests, fixtures) were skipped, so the sample reflects configs people use rather than ones they publish as instructions.
- **Duplicates:** files are stored under their git blob id, which is a hash of the contents, so identical copies (forks, copied templates) were counted once. 23 duplicates were dropped.
- **Result:** 400 files, of which 391 parsed as MCP configs and 9 were not valid JSON. The 391 configs define 600 servers.

To reproduce: `discover-lite fetch-github --limit 400`, then `discover-lite stats data/github-configs/`.

## Findings by check

Only four checks apply to MCP client configs. The others (instructions, tool approval, access settings) need fields these files do not have.

| Check | Severity | Findings | Configs affected | Share of configs |
|---|---|---|---|---|
| secret_in_config | high | 30 | 20 | 5.1% |
| insecure_remote_server (plain HTTP) | high | 1 | 1 | 0.3% |
| unpinned_package | medium | 175 | 103 | 26.3% |
| insecure_remote_server (no Authorization header) | low | 80 | 55 | 14.1% |

## Statistics

| Measure | Count | Share |
|---|---|---|
| Configs parsed | 391 | of 400 files: 97.8% |
| Configs with at least one finding | 157 | 40.2% |
| Configs with a hard-coded secret | 20 | 5.1% |
| Servers | 600 | |
| Local servers (command) | 497 | 82.8% of servers |
| Remote servers (url) | 103 | 17.2% of servers |
| Local servers started by a package runner (npx, uvx, bunx, pnpx) | 192 | 38.6% of local servers |
| Package-runner servers with no exact version | 175 | 91.1% of package-runner servers |
| Package-runner servers asking for `@latest` | 56 | 29.2% of package-runner servers |
| Remote servers on plain HTTP (non-local) | 1 | 1.0% of remote servers |
| Remote servers with no Authorization header | 80 | 77.7% of remote servers |

Most common commands for local servers: npx (156), python (70), node (66), uvx (34), uv (25), docker (19), python3 (17), java (8).

## Three takeaways

1. **Almost nobody pins MCP packages.** 91% of servers started with a package runner have no exact version, and 29% ask for `@latest` by name. Each time the client starts, it may download and run new code with the user's permissions. One compromised release of a popular server would reach these machines with no change to their config.
2. **About one config in twenty contains a hard-coded credential.** 20 of 391 configs (5.1%) contain at least one value the scanner treats as a secret, mostly tokens in recognisable vendor formats. These files are public, so anyone can read those values. This figure is before manual review; see below.
3. **Transport security is mostly fine.** Only 1 of 103 remote servers uses plain HTTP to a non-local host. 78% of remote servers send no Authorization header, but many remote MCP servers sign in with OAuth in the browser instead, so this is not a problem by itself.

## Manual review of secret hits

The secret check is a set of rules, so its hits were reviewed by hand. `discover-lite review-secrets data/github-configs/` lists each hit with its file and a redacted value.

- An earlier version of the rules produced 33 hits. Reviewing them by shape showed four were not secrets: a reference followed by a path, a setting called `AUTH_METHOD`, the literal word `password`, and the Portuguese for "your token". The rules were tightened, leaving 30 hits.
- About five of the 30 look like test or local development values (for example values starting with "test" or "dev"). They still count as hard-coded credentials, but they carry less risk.
- **Case study.** One config contained a key under `AGENT_PRIVATE_KEY` that looked like a blockchain private key. Reading the project around it showed it was an Aptos testnet signing key for a demo; the project's own notes describe the funds as test tokens. The agent address in their documentation has never sent a transaction and holds nothing on either testnet or mainnet. A static scanner cannot tell a testnet key from a mainnet one, so the finding was kept in the count but downgraded in this write-up. It is still bad practice: an Aptos key controls the same address on every network.

**Review status:** the remaining hits are still to be confirmed by hand before a final rate is quoted. Until then, quote it as "about 5% of configs, before manual review".

## Limitations

- **Selection bias.** These are configs people chose to commit to public repositories. People who keep their configs private may behave differently.
- **Search order.** GitHub returns results in best-match order and at most 1,000 per query, so this is a sample, not a census.
- **Rules, not proof.** The secret check uses name and format rules with a placeholder filter. It can miss secrets in unusual formats and can count test values. Values were never checked against the services they belong to.
- **A secret in a file may already be revoked.** The scan reads files as they are on GitHub, not whether a token still works.
- **Configuration, not behaviour.** The scan reads how servers are started. It does not look at what the servers do, whether a package is malicious, or whether a pinned version is a safe one.
- **Not yet covered:** Docker images without a pinned tag or digest (19 servers use docker), and credentials embedded in connection strings.

## Handling of the data

- Raw files are kept only in `data/github-configs/`, which is excluded from git.
- No repository names are stored by the fetcher or named in this document.
- Every secret-like value in any output goes through `redact()`, which keeps only the first three characters.
- Downloaded files are parsed as JSON only. Nothing in them is run.
