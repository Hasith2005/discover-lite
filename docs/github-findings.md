# Findings: public MCP client configs on GitHub

## What was scanned

- **Dates fetched:** 17 October 2026 (first 400 files) and 18 October 2026 (1,668 more)
- **Source:** GitHub code search API, one query per client and file-size range, in GitHub's best-match order. Splitting by file size gets past the limit of 1,000 results per query.
- **Clients and file names:** Claude Code (`.mcp.json`), Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), VS Code (`.vscode/mcp.json`, which uses a `servers` key), Windsurf (`mcp_config.json`) and Cline (`cline_mcp_settings.json`), up to 300 new files each on the second run
- **Filtering:** exact file names only. Paths that look like documentation (example, sample, template, demo, docs, tests, fixtures) were skipped, so the sample reflects configs people use rather than ones they publish as instructions.
- **Duplicates:** files are stored under their git blob id, which is a hash of the contents, so identical copies (forks, copied templates) were counted once. The second run alone dropped 698 duplicates.
- **Result:** 2,068 files, of which 2,009 parsed as MCP configs and 59 did not. The 2,009 configs define 2,533 servers.

To reproduce: `discover-lite fetch-github --limit 1800`, then `discover-lite stats data/github-configs/`.

## Findings by check

| Check | Severity | Findings | Configs affected | Share of configs |
|---|---|---|---|---|
| secret_in_config | high | 51 | 37 | 1.8% |
| insecure_remote_server (plain HTTP) | high | 7 | 7 | 0.3% |
| no_human_in_loop | high | 27 | 3 | 0.1% |
| unpinned_package | medium | 669 | 488 | 24.3% |
| broad_filesystem_access | medium | 2 | 2 | 0.1% |
| insecure_remote_server (no Authorization header) | low | 398 | 344 | 17.1% |
| secret_in_config (typed value: password or placeholder) | low | 28 | 21 | 1.0% |
| unclassified_tool | low | 14 | 6 | 0.3% |

`no_human_in_loop` and `unclassified_tool` can fire on client configs only through Cline's `alwaysAllow` list, which names tools that run without asking the user. 18 servers had a non-empty list.

## Statistics

| Measure | Count | Share |
|---|---|---|
| Configs parsed | 2,009 | of 2,068 files: 97.1% |
| Configs with at least one finding | 825 | 41.1% |
| Configs with a hard-coded secret | 37 | 1.8% |
| Configs with only typed values under secret names (password or placeholder) | 19 | 0.9% |
| Servers | 2,533 | |
| Local servers (command) | 1,937 | 76.5% of servers |
| Remote servers (url) | 594 | 23.5% of servers |
| Local servers started by a package runner (npx, uvx, bunx, pnpx) | 721 | 37.2% of local servers |
| Package-runner servers with no exact version | 669 | 92.8% of package-runner servers |
| Package-runner servers asking for `@latest` | 217 | 30.1% of package-runner servers |
| Remote servers on plain HTTP (non-local) | 7 | 1.2% of remote servers |
| Remote servers with no Authorization header | 398 | 67.0% of remote servers |

Most common commands for local servers: npx (611), python (263), node (257), uv (96), uvx (87), python3 (66), docker (46), bun (23).

## Three takeaways

1. **Almost nobody pins MCP packages.** 93% of servers started with a package runner have no exact version, and 30% ask for `@latest` by name. Each time the client starts, it may download and run new code with the user's permissions. One compromised release of a popular server would reach these machines with no change to their config. The figure barely moved between the first sample of 391 configs (91%) and this one of 2,009, across six clients, so it is a stable result.
2. **About 1 in 60 configs holds a real-looking credential.** 37 of 2,009 configs (1.8%) contain a known vendor key format or a generated-looking value under a secret name. A hand review (below) found that 32 of them look like working keys for live services, among them live-mode payment keys and a database key with full access. A test or demo project does not mean a test key: several real-looking keys sat in tutorials, hackathon entries and coursework.
3. **Transport security is mostly fine; approval settings are the next gap.** 7 of 594 remote servers use plain HTTP to a non-local host. 67% send no Authorization header, but many remote MCP servers sign in with OAuth in the browser instead. Only Cline records which tools skip approval in the config itself; for the other clients that signal lives in separate settings files this scan does not read.

## Fixes found by running on real data

Running on the larger sample exposed two gaps in the connector, both fixed with tests:

- **Windsurf names the remote address `serverUrl`** (and Gemini CLI `httpUrl`), not `url`. 46 remote servers were being missed by the transport checks.
- **`cmd /c npx package` hides the package runner on Windows.** 35 servers were skipped by the version check. The connector now unwraps `cmd /c <program>` when a single program follows; longer shell lines are left alone.

## Manual review of secret hits

`discover-lite review-secrets data/github-configs/` lists each hit with its file and a redacted value.

**First sample.** On the first 391 configs, an earlier version of the rules produced 33 hits. Four were not secrets (a reference followed by a path, a setting called `AUTH_METHOD`, the literal word `password`, and the Portuguese for "your token"), and the rules were tightened.

**Full sample.** Before the change described below, the check produced 78 hits in 55 configs. Each config was traced back to its public repository, and the repository was read (description, README, file list, history of the config file) to judge the value. No key was ever tried against its service, and no repository is named here.

| Judgement | Configs |
|---|---|
| Looks like a real key for a live service (right format and length) | 31 |
| Only works on the owner's machine or on a testnet | 8 |
| Placeholder or example text | 16 |

- 7 of the 31 real-looking keys were in tutorials, demos, hackathon entries or coursework.
- 54 of the 55 files still held the value when reviewed. No commit removing or rotating a key was seen.
- All 16 placeholders were text a person typed: "your key here" in Portuguese, Czech and Chinese, a literal `{secret}`, sample passwords, and demo tokens labelled "public, not reuse".

**What changed in the check.** No list of placeholder words could be complete, so the check now asks whether a value looks *generated* rather than whether it looks like a known placeholder:

- **Vendor key formats come from gitleaks' published rules** (version 8.30.1, 220 rules), applied with gitleaks' own keyword, entropy and known-example tests. The project no longer keeps its own list of key prefixes.
- **Otherwise, a value under a secret-sounding name is high** only if, with separators removed, it is at least 16 characters, mixes letters and digits, and has an entropy of at least 3.0 bits per character.
- **Anything else under a secret-sounding name is low**: shown in scans, but not counted in the rate above.

Against the hand judgements, all 31 real-looking configs stay high, 15 of the 16 placeholder configs move to low, and 4 of the 8 local or testnet configs stay high. Running gitleaks' rules on the data also found one real leak the old rules missed (a token passed as a command-line header argument) and, before gitleaks' keyword test was added, one false one (a git commit hash in a package pin). gitleaks' list of stopwords for its generic rule was tried as well and rejected: it dropped three real keys, for example because the prefix `tvly-dev-` contains the stopword `dev-`.

**Rate to quote:** 37 of 2,009 configs (1.8%) hold a hard-coded secret; by hand review, about 32 (1.6%) look like working credentials for live services.

**Case study.** One config contained a key under `AGENT_PRIVATE_KEY` that looked like a blockchain private key. Reading the project around it showed it was an Aptos testnet signing key for a demo; the project's own notes describe the funds as test tokens. The agent address in their documentation has never sent a transaction and holds nothing on either testnet or mainnet. A static scanner cannot tell a testnet key from a mainnet one, so the finding stays high. It is still bad practice: an Aptos key controls the same address on every network.

## Limitations

- **Selection bias.** These are configs people chose to commit to public repositories. People who keep their configs private may behave differently.
- **Search order.** GitHub returns results in best-match order and at most 1,000 per query, so this is a sample, not a census.
- **Rules, not proof.** The secret check uses gitleaks' vendor formats, name rules and a randomness test. Its thresholds were checked on the same hits that were reviewed by hand, so a fresh sample is the real test. It misses passwords a person chose (they look typed) and keys in formats nobody has written a rule for, and how many it misses has not been measured. Values were never checked against the services they belong to.
- **A secret in a file may already be revoked.** The scan reads files as they are on GitHub, not whether a token still works.
- **Configuration, not behaviour.** The scan reads how servers are started. It does not look at what the servers do, whether a package is malicious, or whether a pinned version is a safe one.
- **Not yet covered:** Docker images without a pinned tag or digest (46 servers use docker), credentials embedded in connection strings, and client approval settings stored outside the server list.
- **No per-client breakdown.** Files are stored by content hash only, so the statistics are for all clients together.

## Handling of the data

- Raw files are kept only in `data/github-configs/`, which is excluded from git.
- No repository names are stored by the fetcher or named in this document.
- Every secret-like value in any output goes through `redact()`, which keeps only the first three characters.
- Downloaded files are parsed as JSON only. Nothing in them is run.
