# What each platform tells us

Draft, 18 October 2026; Foundry added 20 October 2026. Written for the people who decide which signals Discover should collect next.

A posture check can only judge a signal the platform gives us. This note sets out, for each platform Discover Lite reads, which security signals are available, which are missing, and the one signal I would most want added. `discover-lite coverage <folder>` prints the same picture as a table for any scan.

Coverage on the synthetic estate in `fixtures/`:

| Signal | bedrock_agent | copilot_studio | foundry_agent | mcp_client |
|---|---|---|---|---|
| Instructions | 2/2 | 0/7 | 2/2 | 0/3 |
| Tools | 2/2 | 7/7 | 2/2 | 0/3 |
| MCP servers | 0/2 | 0/7 | 2/2 | 3/3 |
| Untrusted knowledge flag | 0/2 | 7/7 | 1/2 | 0/3 |
| Authentication setting | 0/2 | 7/7 | 0/2 | 0/3 |
| Sharing setting | 0/2 | 7/7 | 0/2 | 0/3 |
| Topics | 0/2 | 0/7 | 0/2 | 0/3 |
| Guardrail setting | 2/2 | 0/7 | 1/2 | 0/3 |
| Tool approval setting (tools) | 3/8 | 6/13 | 4/8 | - |

A zero in this table is a gap in what we can see, not a clean result. Checks never fire on a missing value.

## Microsoft Copilot Studio

**Source.** One agent record from the Power Platform inventory, using only fields in Microsoft's [agent inventory schema](https://learn.microsoft.com/microsoft-copilot-studio/admin-agent-inventory): `properties.displayName`, `authentication`, `sharedWithViewers.entireTenant`, `IsWebSearchEnabledForKnowledge`, and `powerPlatformConnectors[]` with `connectorId` and `operations[]` (`operationId`, `usedAs`, `requiresEndUserConsent`). Values in the fixtures are synthetic. Standard connectors carry their real IDs (`shared_office365`, `shared_office365users`, `shared_sharepointonline`); custom connectors have no `connectorId` in the fixtures, because their IDs are environment-specific and I found no documented format to copy.

**Available.** Who can use the agent (authentication mode, tenant-wide sharing), whether it searches the web, which connector operations it can call and whether each asks for the user's consent. These signals support four checks: `open_access`, `prompt_injection_exposure`, `no_human_in_loop` and `unclassified_tool`.

**Missing.** The agent's instructions and topics: the inventory does not include them, so `missing_scope` and `topic_overlap` cannot run on Copilot Studio. What an operation actually does: the inventory names operations (`SendEmailV2`) but does not say whether they read or write, so we fall back to a word list that marks unclear names as unknown (3 of 13 Copilot tools in the fixtures). No guardrail or content-filter setting, and consent is only present on some operations (6 of 13 tools say either way).

**Most wanted.** The instructions and topics. Copilot Studio keeps agents in the environment's Dataverse database; whether its read-only API exposes them, and in which fields, is the next thing to research. After that, the HTTP method of each operation: `connectorId` names the connector, whose OpenAPI definition would give GET (read) or POST, PUT, PATCH and DELETE (change) in place of a guess from the name.

## AWS Bedrock Agents

**Source.** Saved responses from the read-only `bedrock-agent` API, one file per call: `GetAgent`, and `GetAgentActionGroup` for each action group (listed by `ListAgentActionGroups`). The connector joins them on `agentId` and `agentVersion`, which both responses carry, so nothing in the format is ours.

**Available.** Instructions, the foundation model, whether a guardrail is attached (`guardrailConfiguration`), each action group's state, and for function-style action groups a per-function `requireConfirmation` (ENABLED or DISABLED). AWS documents confirmation as a defence against actions triggered by prompt injection, so it maps directly to `no_human_in_loop`. OpenAPI-style action groups include the HTTP method of each operation, which gives a reliable read or write label. The built-in code interpreter is visible through `parentActionGroupSignature`.

**Missing.** Who can invoke the agent: access is controlled by IAM policies, which `GetAgent` does not show, so `open_access` cannot run. Whether the agent reads untrusted content: knowledge bases (`ListAgentKnowledgeBases`) are not read yet. Confirmation for OpenAPI-style operations is not read by our connector.

**Most wanted.** The data source types of each attached knowledge base (`ListAgentKnowledgeBases`, then the knowledge base's data sources). A web crawler data source is untrusted content, which would let `prompt_injection_exposure` run on Bedrock, where today it never can.

## Microsoft Foundry Agent Service

**Source.** The read-only Foundry Agent Service REST API, `api-version=v1`: `GET {endpoint}/agents/{name}` returns an `AgentObject` whose newest version is under `versions.latest`, and `GET {endpoint}/agents/{name}/versions/{version}` returns one `AgentVersionObject`. The connector reads either response as saved, with no bundling of our own. Field names and meanings are from the [Foundry REST reference](https://learn.microsoft.com/rest/api/microsoft-foundry/aiproject) and the [MCP tool guide](https://learn.microsoft.com/azure/foundry/agents/how-to/tools/model-context-protocol). This is the current Foundry agent API; the older Assistants-style agents have their own [migration guide](https://learn.microsoft.com/azure/foundry/agents/how-to/migrate).

**Available.** Each version's `definition` gives the agent kind (`prompt`, `hosted`, `workflow` or `container_app`), the model deployment, `instructions` (prompt agents only) and a typed `tools` array. The tool types carry real security signals:

- `mcp` tools give the server address (`server_url`), any `headers`, an `allowed_tools` list and `require_approval`. Microsoft documents `always` as the default when `require_approval` is left out, so a missing setting is a firm "approval required", and `never` is an explicit "no approval". It can also be set per tool (`{"always": {"tool_names": [...]}, "never": {...}}`). This is the human-in-the-loop signal, and it feeds `no_human_in_loop` directly.
- `openapi` tools include the whole OpenAPI spec, so every operation's HTTP method gives a reliable read or write label, plus the outbound auth type (`anonymous`, `project_connection` or `managed_identity`).
- `web_search`, `bing_grounding`, `bing_custom_search_preview` and `browser_automation_preview` bring in open-web content, which lets `prompt_injection_exposure` run.
- `code_interpreter`, `shell` and `local_shell` run code the model writes.
- `rai_config.rai_policy_name` names a content-filter policy attached to the agent itself.

These support `no_human_in_loop`, `prompt_injection_exposure`, `missing_scope`, `unclassified_tool` and `secret_in_config` (on MCP headers).

**Missing.** Who can call the agent: access is Azure RBAC on the project, which the agent responses do not show, so `open_access` cannot run. Who created or owns the agent: the version object has no creator field. Whether a content filter applies when there is no `rai_config`: the model deployment has its own filter (Microsoft's default is `Microsoft.DefaultV2`), which is not part of the agent, so the connector records "does not say" rather than "no guardrail". How an MCP or A2A tool authenticates: `project_connection_id` only names a project connection, so a missing Authorization header is not reported for Foundry. The tools behind an MCP server that has no `allowed_tools` list: finding them means connecting to the server.

**Most wanted.** The project connections each tool references (the project's connections API), and the role assignments on the project. The first says how each tool authenticates and whether credentials are shared; the second says who can run the agent, which is the `open_access` signal Foundry is missing today.

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
- **Google ADK, LangChain.** Not yet researched for this project. ADK and LangChain agents are defined in code, so the likely route is reading project files (the same approach as MCP configs) rather than calling an API.
