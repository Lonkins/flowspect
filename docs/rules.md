# Rule catalog

flowspect ships 27 rules. Each is authored in the [rule DSL](writing-rules.md);
add your own with `--rules`. This page is generated from the bundled pack.

| Rule | Severity | Kind | What it finds |
|------|----------|------|---------------|
| `FS-INJECT-DESERIALIZE-001` | 🔴 critical | taint | Untrusted input to unsafe deserialization |
| `FS-INJECT-EXEC-001` | 🔴 critical | taint | Prompt injection to code execution |
| `FS-INJECT-SQL-001` | 🔴 critical | taint | Prompt injection to SQL execution |
| `FS-TRIFECTA-001` | 🔴 critical | taint | Lethal trifecta (untrusted input + private data + exfiltration) |
| `FS-INDIRECT-EXEC-001` | 🟠 high | taint | Fetched content to code execution |
| `FS-INDIRECT-SQL-001` | 🟠 high | taint | Fetched content to SQL execution |
| `FS-INDIRECT-TRIFECTA-001` | 🟠 high | taint | Fetched content + private data + exfiltration |
| `FS-INJECT-FILEWRITE-001` | 🟠 high | taint | Untrusted input to file write |
| `FS-INJECT-STATECHANGE-001` | 🟠 high | taint | Untrusted input to state-changing action |
| `FS-SECRET-HTTP-001` | 🟠 high | taint | Credential to outbound HTTP |
| `FS-SECRET-MESSAGING-001` | 🟠 high | taint | Credential to messaging sink |
| `FS-SSRF-001` | 🟠 high | taint | SSRF via user-controlled fetch URL |
| `FS-WEBHOOK-UNAUTH-001` | 🟠 high | structural | Unauthenticated trigger performs state change |
| `FS-DESERIALIZE-NODE-001` | 🟡 medium | structural | Unsafe deserialization component present |
| `FS-FILEREAD-EXFIL-001` | 🟡 medium | taint | Local file contents to external sink |
| `FS-HARDCODED-SECRET-001` | 🟡 medium | structural | Hardcoded secret in flow export |
| `FS-MEMORY-EXFIL-001` | 🟡 medium | taint | Conversation memory to external sink |
| `FS-OVERBROAD-CODE-TOOL-001` | 🟡 medium | structural | Unrestricted code-execution tool |
| `FS-SENSITIVE-HTTP-001` | 🟡 medium | taint | Sensitive data to outbound HTTP |
| `FS-SENSITIVE-MESSAGING-001` | 🟡 medium | taint | Sensitive data to messaging sink |
| `FS-TOOLRESULT-NOVALIDATE-001` | 🟡 medium | taint | Unvalidated tool result reaches a sink |
| `FS-UNTRUSTED-HTTP-001` | 🟡 medium | taint | Untrusted input to outbound HTTP body |
| `FS-UNTRUSTED-MESSAGING-001` | 🟡 medium | taint | Untrusted input relayed to messaging sink |
| `FS-WEBFETCH-STATECHANGE-001` | 🟡 medium | taint | Fetched content drives a state change |
| `FS-OVERBROAD-SQL-TOOL-001` | 🔵 low | structural | Direct SQL-execution tool |
| `FS-SENSITIVE-SUBFLOW-001` | 🔵 low | taint | Sensitive data crosses into a sub-flow |
| `FS-SUBFLOW-UNTRUSTED-001` | 🔵 low | taint | Untrusted input crosses into a sub-flow |

## Rule details

### `FS-INJECT-DESERIALIZE-001` — Untrusted input to unsafe deserialization

**Severity:** critical · **Kind:** taint

Untrusted input reaches a node that deserializes data (pickle/eval-style). Unsafe deserialization of attacker-controlled bytes is remote code execution.

**Remediation:** Deserialize only trusted data, use a safe format (JSON with a schema), and never unpickle or eval attacker-influenced content.

**References:** [1](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)

### `FS-INJECT-EXEC-001` — Prompt injection to code execution

**Severity:** critical · **Kind:** taint

Untrusted input flows into a node that executes code or shell commands with no validation in between. A crafted payload or prompt injection can be turned into arbitrary execution.

**Remediation:** Never let untrusted text reach a code/shell node directly. Constrain the tool to a fixed command set, validate arguments against an allowlist, or insert an output-validation guard before execution.

**References:** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

### `FS-INJECT-SQL-001` — Prompt injection to SQL execution

**Severity:** critical · **Kind:** taint

Untrusted input reaches a node that runs SQL against a live database. Attacker-controlled text can drive injection or destructive queries.

**Remediation:** Use parameterised queries, restrict the database role to read-only where possible, and validate the model/tool output before it becomes SQL.

**References:** [1](https://owasp.org/www-community/attacks/SQL_Injection)

### `FS-TRIFECTA-001` — Lethal trifecta (untrusted input + private data + exfiltration)

**Severity:** critical · **Kind:** taint

Untrusted input reaches a sink that can send data outside the flow, and that same sink is also reachable from private/sensitive data. An attacker who controls the input can steer the flow into exfiltrating the private data — the classic "lethal trifecta" of agent security.

**Remediation:** Break one leg of the trifecta: gate the exfiltration sink behind validated output, remove the private-data source from this path, or require human approval before the outbound action.

**References:** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

### `FS-INDIRECT-EXEC-001` — Fetched content to code execution

**Severity:** high · **Kind:** taint

Content pulled from the web (inherently untrusted) reaches a code/shell execution node — a second-order (indirect) prompt-injection path where the attacker controls a page the flow fetches.

**Remediation:** Treat fetched content as untrusted. Do not let it drive code execution; validate or constrain the executor.

**References:** [1](https://simonwillison.net/tags/prompt-injection/)

### `FS-INDIRECT-SQL-001` — Fetched content to SQL execution

**Severity:** high · **Kind:** taint

Web-fetched content reaches a SQL execution node, an indirect-injection path into the database.

**Remediation:** Parameterise queries and validate fetched content before it influences SQL.

### `FS-INDIRECT-TRIFECTA-001` — Fetched content + private data + exfiltration

**Severity:** high · **Kind:** taint

Web-fetched (untrusted) content reaches an exfiltration sink that is also reachable from private data — the lethal trifecta driven by indirect injection rather than direct user input.

**Remediation:** Break the path: gate the exfil sink on validated output or remove the private data from a flow that also ingests web content.

### `FS-INJECT-FILEWRITE-001` — Untrusted input to file write

**Severity:** high · **Kind:** taint

Untrusted input reaches a node that writes files. Attacker-controlled paths or contents enable overwrite, path traversal, or planting executable content.

**Remediation:** Constrain the write path to a fixed directory, sanitise filenames, and never let untrusted text choose the destination path.

### `FS-INJECT-STATECHANGE-001` — Untrusted input to state-changing action

**Severity:** high · **Kind:** taint

Untrusted input reaches a node that performs a state-changing side effect (CRUD call, DB write, external mutation) without validation.

**Remediation:** Validate and authorise the action before it fires; require confirmation for destructive operations driven by untrusted input.

### `FS-SECRET-HTTP-001` — Credential to outbound HTTP

**Severity:** high · **Kind:** taint

A node holding secrets/credentials flows into an outbound HTTP request, risking credential leakage to an external endpoint.

**Remediation:** Do not route credential-bearing values into request bodies or query strings. Reference secrets only inside the authenticated node that needs them.

### `FS-SECRET-MESSAGING-001` — Credential to messaging sink

**Severity:** high · **Kind:** taint

A node holding secrets/credentials flows into a messaging sink (email, chat, webhook), risking credential disclosure to a channel.

**Remediation:** Never forward credentials into message contents. Redact secrets before any messaging node.

### `FS-SSRF-001` — SSRF via user-controlled fetch URL

**Severity:** high · **Kind:** taint

Untrusted input flows into a fetch/HTTP node whose URL it can influence, enabling server-side request forgery against internal services or metadata endpoints.

**Remediation:** Allowlist destination hosts, forbid internal/link-local ranges, and never let untrusted text set the request URL directly.

**References:** [1](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

### `FS-WEBHOOK-UNAUTH-001` — Unauthenticated trigger performs state change

**Severity:** high · **Kind:** structural

A node that both receives untrusted input and performs a state-changing action (e.g. an n8n webhook wired to a mutation) carries no authentication capability — anyone who can reach the endpoint can trigger the action.

**Remediation:** Require authentication on the trigger (header auth, HMAC signature, or a gateway) before it performs any state change.

### `FS-DESERIALIZE-NODE-001` — Unsafe deserialization component present

**Severity:** medium · **Kind:** structural

A node performs unsafe deserialization (pickle/eval-style). These components are dangerous even before considering data flow.

**Remediation:** Remove the component or replace it with a safe, schema-validated parser.

### `FS-FILEREAD-EXFIL-001` — Local file contents to external sink

**Severity:** medium · **Kind:** taint

Content read from the local filesystem flows to an outbound HTTP or messaging sink — a local-file exfiltration path.

**Remediation:** Confirm the file is meant to leave the environment and redact sensitive portions before any external sink.

### `FS-HARDCODED-SECRET-001` — Hardcoded secret in flow export

**Severity:** medium · **Kind:** structural

A node carries an inline credential embedded in the export file. Secrets in an exported flow leak wherever the file travels (git, sharing, backups).

**Remediation:** Move the credential to an environment variable or the builder's secret store and re-export. Rotate any secret already committed.

**References:** [1](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)

### `FS-MEMORY-EXFIL-001` — Conversation memory to external sink

**Severity:** medium · **Kind:** taint

Conversation/long-term memory (which can accumulate prior sensitive context) flows to an outbound HTTP or messaging sink.

**Remediation:** Do not forward raw memory to external sinks; select and redact the specific fields required.

### `FS-OVERBROAD-CODE-TOOL-001` — Unrestricted code-execution tool

**Severity:** medium · **Kind:** structural

A code/shell execution component is present. An agent tool that runs arbitrary code is the broadest possible scope and turns any upstream injection into execution.

**Remediation:** Replace with a purpose-built tool exposing only the operations needed, or sandbox the executor and restrict its capabilities.

### `FS-SENSITIVE-HTTP-001` — Sensitive data to outbound HTTP

**Severity:** medium · **Kind:** taint

Private/sensitive data (vector store, DB read, internal files) flows to an outbound HTTP request. Even without untrusted input this is a data-egress path.

**Remediation:** Confirm the destination is trusted and the data is meant to leave. Add an output-validation/redaction step before the request.

### `FS-SENSITIVE-MESSAGING-001` — Sensitive data to messaging sink

**Severity:** medium · **Kind:** taint

Private/sensitive data flows to a messaging sink (email, chat), a common accidental-disclosure path.

**Remediation:** Verify the recipient channel is authorised for this data and redact fields that should not be shared.

### `FS-TOOLRESULT-NOVALIDATE-001` — Unvalidated tool result reaches a sink

**Severity:** medium · **Kind:** taint

A tool result from a web-fetch node reaches a messaging, outbound-HTTP, or state-changing sink with no output-validation guard on the path — missing validation of tool output.

**Remediation:** Add an output-validation/guardrail node between tool results and any sink that acts on them.

### `FS-UNTRUSTED-HTTP-001` — Untrusted input to outbound HTTP body

**Severity:** medium · **Kind:** taint

Untrusted input reaches an outbound HTTP request. Beyond SSRF, this lets an attacker shape requests the flow makes to third-party services.

**Remediation:** Validate and constrain the request; never forward raw untrusted input into an outbound call.

### `FS-UNTRUSTED-MESSAGING-001` — Untrusted input relayed to messaging sink

**Severity:** medium · **Kind:** taint

Untrusted input flows to a messaging sink (email, chat, webhook). Without validation this enables spam, phishing relay, or social-engineering through the flow's trusted identity.

**Remediation:** Validate and rate-limit messages derived from untrusted input; do not let arbitrary content be sent under the flow's identity.

### `FS-WEBFETCH-STATECHANGE-001` — Fetched content drives a state change

**Severity:** medium · **Kind:** taint

Web-fetched (untrusted) content reaches a state-changing action, letting an attacker-controlled page influence a mutation.

**Remediation:** Validate fetched content before it drives any side effect; require confirmation for destructive actions.

### `FS-OVERBROAD-SQL-TOOL-001` — Direct SQL-execution tool

**Severity:** low · **Kind:** structural

A node executes SQL directly. Direct database access is a broad scope; prefer narrow, parameterised operations.

**Remediation:** Expose specific queries or stored procedures instead of arbitrary SQL, and use a least-privilege database role.

### `FS-SENSITIVE-SUBFLOW-001` — Sensitive data crosses into a sub-flow

**Severity:** low · **Kind:** taint

Private/sensitive data flows into a sub-flow whose downstream sinks flowspect cannot see. The data may be exfiltrated inside the callee.

**Remediation:** Review the referenced sub-flow for egress sinks; pass only the minimum data across the boundary.

### `FS-SUBFLOW-UNTRUSTED-001` — Untrusted input crosses into a sub-flow

**Severity:** low · **Kind:** taint

Untrusted input flows into a sub-flow/opaque workflow reference. flowspect cannot see inside the sub-flow, so any sink it contains is unanalysed — review the callee for the trifecta and injection sinks.

**Remediation:** Audit the referenced sub-flow with flowspect as well; validate inputs at the boundary before delegating.
