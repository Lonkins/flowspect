# How the taint engine works

The engine answers one question over the [Graph IR](ir.md): is there a directed
data-flow path from a **source** node to a **sink** node that no **sanitizer**
neutralises? Rules resolve their capability matchers to node-id sets and call it.

```python
from flowspect.engine import find_taint_paths

paths = find_taint_paths(
    graph,
    sources={"ChatInput-1"},
    sinks={"PythonREPL-1"},
    sanitizers={"Guard-1"},
)
# each path: source, sink, and the full node sequence between them
```

## Traversal rules

**Data edges** propagate taint forward (`source → target`).

**Tool edges propagate both ways.** Every builder draws an agent's tool as
`tool → agent`. The tool result flows forward into the agent, *and* the agent —
now possibly carrying injected instructions — controls the tool's arguments, so
taint also flows `agent → tool`. Without the reverse direction, the entire
prompt-injection→execution class is invisible.

**Sanitizers stop propagation.** Taint that reaches a sanitizer node is neutralised:
it does not flow to that node's successors, and the sanitizer itself is not reported
as a tainted sink. This is the standard taint model — a validated boundary cleans
the data crossing it.

**Unknown and sub-flow nodes are taint-transparent.** A component the importer
doesn't recognise, or an opaque sub-flow reference, passes taint straight through.
That's the conservative choice: flowspect assumes taint flows unless it has a reason
to believe otherwise.

**Loops terminate.** Traversal is breadth-first with a visited set, so cycles and
back-edges converge instead of looping forever. The shortest path to each sink wins.

## What it reports

One canonical (shortest) path per `(source, sink)` pair. Enumerating every path is
exponential and adds no signal for a reviewer — the shortest witness is enough to
locate and fix the flow.

A source that is itself a sink is not reported: taint must *flow* to a distinct sink
for there to be a data-flow finding.

## Fan-in, fan-out, sub-flows

- **Fan-out** — a source feeding several sinks yields one finding per reachable sink.
- **Fan-in** — a sink reachable from several sources yields one finding per source,
  each with its own path, so attribution is precise.
- **Sub-flows** — treated as opaque pass-throughs; the
  `FS-SUBFLOW-*` rules flag when tainted or sensitive data crosses into a sub-flow
  whose internals flowspect cannot see.

## Why not regex?

Regex over the export JSON can tell you a Python node and a chat node both exist. It
can't tell you whether data actually flows from one to the other through five
intermediate nodes and a reversed tool binding. flowspect answers reachability, not
co-occurrence — that's the difference between a real finding and a guess.
