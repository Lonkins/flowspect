# Write your own rule

Rules are YAML. Point flowspect at a file or directory with `--rules` to add them
to (or, with `--no-builtin`, replace) the bundled pack.

```bash
flowspect scan flow.json --rules ./my-rules/
```

## Node matchers

Both rule kinds select nodes with a **matcher** — an AND of any of these fields:

```yaml
capability: code_execution        # node has this capability
any_capabilities: [outbound_http, messaging]   # has at least one
all_capabilities: [llm, secrets]  # has all
type_equals: PythonREPL           # exact builder component type
type_regex: "(?i)python"          # regex over the type
config_equals: { method: POST }   # normalized config field equals value
negate: true                      # invert the whole matcher
```

A matcher must declare at least one constraint.

## Taint rules

Assert there is **no unsanitised path** from a source class to a sink class.

```yaml
id: MY-INJECT-001
kind: taint
severity: high        # critical | high | medium | low
title: User input reaches the shell
description: >
  Untrusted input flows into a shell node without validation.
remediation: >
  Constrain the shell to a fixed command set.
references:
  - https://example.com/writeup
source: { capability: untrusted_input }
sink: { capability: code_execution }
sanitizer: { capability: output_validation }   # optional: neutralises the flow
```

Optional gates sharpen the assertion:

```yaml
# The sink must ALSO be reachable from a second class (this is how the lethal
# trifecta requires private data to converge on the exfiltration sink):
also_reachable_from: { capability: sensitive_data }

# The tainted path must pass through a matching node:
path_contains: { capability: llm }
```

A finding is emitted for each source→sink path that survives the sanitizer and
gates, carrying the exact node sequence.

## Structural rules

A per-node predicate — the finding is a property of one node, not a flow.

```yaml
id: MY-WEBHOOK-001
kind: structural
severity: high
title: Unauthenticated webhook triggers a state change
match: { all_capabilities: [untrusted_input, state_change] }
require: { capability: authentication }   # matched node MUST also satisfy this
```

Use `forbid` instead of `require` to flag nodes that *do* match something they
shouldn't. Omit both to flag **every** matched node — for "the mere presence of
this component is the problem" rules:

```yaml
id: MY-DESERIALIZE-001
kind: structural
severity: medium
title: Unsafe deserialization component present
match: { capability: deserialization }
```

## Validation

The loader validates every rule and aggregates errors so you see them all at once:

```bash
flowspect rules --rules ./my-rules/     # loads + lists, or prints all errors
```

Rules ids must match `^[A-Z0-9][A-Z0-9-]*$`. A taint rule requires `source` and
`sink`; a structural rule requires `match`. Setting a field that doesn't belong to
the rule's kind is an error.

## Testing your rules

Give each rule a flow it must flag and one it must not — the same true-positive /
false-positive discipline the bundled pack uses. A safe variant is usually the
vulnerable flow with a sanitizer inserted or the offending edge removed.
