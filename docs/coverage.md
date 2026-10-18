# What each platform tells us

Draft, 18 October 2026. Written for the people who decide which signals Discover should collect next.

A posture check can only judge a signal the platform gives us. This note sets out, for each platform Discover Lite reads, which security signals are available, which are missing, and the one signal I would most want added. `discover-lite coverage <folder>` prints the same picture as a table for any scan.

Coverage on the synthetic estate in `fixtures/`:

| Signal | bedrock_agent | copilot_studio | mcp_client |
|---|---|---|---|
| Instructions | 2/2 | 7/7 | 0/3 |
| Tools | 2/2 | 7/7 | 0/3 |
| MCP servers | 0/2 | 0/7 | 3/3 |
| Untrusted knowledge flag | 0/2 | 7/7 | 0/3 |
| Authentication setting | 0/2 | 7/7 | 0/3 |
| Sharing setting | 0/2 | 7/7 | 0/3 |
| Topics | 0/2 | 6/7 | 0/3 |
| Guardrail setting | 2/2 | 0/7 | 0/3 |
| Tool approval setting (tools) | 3/8 | 6/13 | - |

A zero in this table is a gap in what we can see, not a clean result. Checks never fire on a missing value.

## Microsoft Copilot Studio

**Source.** A synthetic export modelled on Microsoft's agent inventory schema (`properties.authentication`, `sharedWithViewers.entireTenant`, `IsWebSearchEnabledForKnowledge`, `powerPlatformConnectors[].operations[]` with `usedAs` and `requiresEndUserConsent`). `instructions`, `topics` and each operation's HTTP `method` are our own additions.

**Available.** Who can use the agent (authentication mode, tenant-wide sharing), whether it searches the web, which connector operations it can call and whether each asks for the user's consent. These signals support five checks: `open_access`, `prompt_injection_exposure`, `no_human_in_loop`, `unclassified_tool` and, with our additions, `missing_scope` and `topic_overlap`.

**Missing.** What an operation actually does. The inventory names operations (`SendEmailV2`) but does not say whether they read or write, so we fall back to a word list that marks unclear names as unknown. 3 of 21 tools in the estate end up unknown. Also missing: no guardrail or content-filter setting, and consent is only present on some operations (6 of 13 tools say either way).

**Most wanted.** The HTTP method of each connector operation, from the connector's OpenAPI definition. GET means read; POST, PUT, PATCH and DELETE mean change. It would replace a guess based on the name with a fact, and the name could only make a tool look more dangerous, never less. The connector already uses the method when it is present.

## AWS Bedrock Agents

**Source.** The read-only `bedrock-agent` API: `GetAgent`, then `ListAgentActionGroups` and `GetAgentActionGroup`. Our file bundles those responses; field names are AWS's own.

**Available.** Instructions, the foundation model, whether a guardrail is attached (`guardrailConfiguration`), each action group's state, and for function-style action groups a per-function `requireConfirmation` (ENABLED or DISABLED). AWS documents confirmation as a defence against actions triggered by prompt injection, so it maps directly to `no_human_in_loop`. OpenAPI-style action groups include the HTTP method of each operation, which gives a reliable read or write label. The built-in code interpreter is visible through `parentActionGroupSignature`.

**Missing.** Who can invoke the agent: access is controlled by IAM policies, which `GetAgent` does not show, so `open_access` cannot run. Whether the agent reads untrusted content: knowledge bases are not in our bundle. Confirmation for OpenAPI-style operations is not read by our connector.

**Most wanted.** The data source types of each attached knowledge base (`ListAgentKnowledgeBases`, then the knowledge base's data sources). A web crawler data source is untrusted content, which would let `prompt_injection_exposure` run on Bedrock, where today it never can.

## MCP clients (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline)

**Source.** The client's own config file (`mcpServers`, or `servers` for VS Code). Remote addresses appear as `url`, `serverUrl` (Windsurf) or `httpUrl` (Gemini CLI). Real public examples come from GitHub; see `docs/github-findings.md`.

**Available.** How each server is started (command, package and version), environment variables and headers (where hard-coded secrets live), remote URLs and their scheme, and the folders a filesystem server is given. These support `secret_in_config`, `unpinned_package`, `insecure_remote_server` and `broad_filesystem_access`.

**Missing.** Which tools each server offers: finding out means starting the server, which a static scanner must never do. Whether tool calls need approval: for most clients that lives in separate settings, not in the server list. The exception, found in the real data, is Cline's `alwaysAllow` list, which names tools that run without asking; the connector turns each into a tool with approval off, and 18 of 2,240 servers in the GitHub sample had one. No instructions, sharing or authentication: a config file belongs to one person.

**Most wanted.** The client's tool permission settings, for example the allow and deny lists in Claude Code's `settings.json`. They say which MCP tools run without asking, which is the human-in-the-loop signal for this whole platform.

## The official MCP Registry

**Source.** The public registry API; see `docs/registry-findings.md`.

**Available.** Package type, name and version, remote endpoints and their scheme, and which environment variables a server declares as secret.

**Missing.** Tools and authentication. The registry describes how a server is installed, not what it can do or who can reach it.

**Most wanted.** The server's tool list with MCP tool annotations (`readOnlyHint`, `destructiveHint`). These are claims made by the publisher, so they could raise a risk but should never lower one; even so, they would be the first published signal of what each server can change.

## Platforms not yet covered

- **OpenAI.** The Assistants API, which stored agents as objects with instructions and tools, was shut down on 26 August 2026, along with Azure OpenAI's Assistants API. There is no longer a stored assistant object to inventory, so discovery for new OpenAI agents has to start from wherever their definitions now live. This needs research before a connector is worth building.
- **Azure AI Foundry, Google ADK, LangChain.** Not yet researched for this project. ADK and LangChain agents are defined in code, so the likely route is reading project files (the same approach as MCP configs) rather than calling an API.
