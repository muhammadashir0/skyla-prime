# SKYLA PRIME — Autonomous Agent Specification

## Implemented agents

| Agent | Role | Permissions |
|---|---|---|
| executive | General execution, coordination | Model calls; no direct side-effects |
| research | Evidence gathering, cited synthesis | Model calls + knowledge retrieval |
| engineering | Software design/implementation | Model calls + sandbox (L2+) |
| operations | Email/calendar/meeting coordination | Connector reads (L0–1), writes (L2+) |
| verification | Independent review of completed work | Model calls; read-only |

## Rules

- Agents have explicit roles and never perform external side-effects
  directly — side-effects go through connectors with autonomy checks.
- The verification agent is always distinct from the executor.
- Every agent execution is persisted as a task step with model + cost.
- Parallel execution for independent steps; sequential where dependencies
  exist (dependency graph from the planner).

## Roadmap

Dedicated science/mathematics agents (symbolic solvers, simulators),
business/communication agents, per-agent budgets/timeouts, agent
disagreement tracking, and multi-agent debate for high-stakes decisions.
