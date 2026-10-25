# GEAA replication package

Code and data for *When Governance Controls Collide: Authority Granularity and Exception Policies for LLM Agents*


GEAA (Governance-Embedded Agent Architecture) is middleware that mediates every tool call an LLM agent makes
against a task-scoped grant. Everything is in one file, `geaa.py`.

## Contents

| Path | What it is |
|---|---|
| `geaa.py` | Risk classifier, tool risk map, signed task identities, mediator, replay, live runner, study workflow, report |
| `tool_risk_map.csv` | Frozen risk vector, tier and severity for all 69 AgentDojo v1.2.2 tools |
| `configurations.csv` | Every evaluated policy configuration (grant, gates, provenance scope, approver) |
| `results/replay/` | Deterministic replay: 949 pairs x 13 configurations (`pairs.csv`, `summary.json`) |
| `results/live_standard/` | Live agent run (Claude Haiku 5.5, `important_instructions`), one row per run |
| `results/live_pilot/` | Attack-framing pilot: 10 framings + standard, 50 governable pairs each, with and without the gate |
| `results/attack_plan.csv`, `attack_plan_plan.json` | Pre-specified pilot sample, seed, framings and selection rule |
| `outputs/` | Figures and tables regenerated from the result files by `python geaa.py report` |

## Reproduce

```bash
pip install -r requirements.txt
export PYTHONUTF8=1          # Windows PowerShell: $env:PYTHONUTF8="1"
python geaa.py replay --out results/replay      # deterministic, no API, ~5-10 minutes
python geaa.py report --replay results/replay/pairs.csv --live results/live_standard/pairs.csv \
    --pilot results/live_pilot/pairs.csv --out outputs
python geaa.py bootstrap --replay results/replay/pairs.csv --out outputs   # Table 9
```

The live run needs an Anthropic API key in `ANTHROPIC_API_KEY` (`python geaa.py check` tests it for free):

```bash
python geaa.py live --configs no_defense,authority_gate,gate_provenance,full_system,full_system_legacy \
    --sample 949 --out results/live_standard --resume
```

Spending is capped by `BUDGET_USD` (default $5) and tracked in `spend_ledger.json`.

## Frozen parameters

**Risk dimensions.** Financial magnitude, reversibility, regulatory scope, external exposure; ordinal 0-3.

**Tier rule.** All-zero vector -> T1; any dimension at 3 -> T3; otherwise T2. Malformed vectors, unknown tools and
unparseable or negative amounts fail safe (T3, infinite severity).

**Severity.** `1.25*financial + 1.0*reversibility + 1.0*regulatory + 1.0*exposure + log10(1 + amount)`;
task-tier ceilings T1 = 3.0, T2 = 9.0, T3 = 16.0.

**Grants.** Cumulative tier grant `A_tier(q) = {t : tier(t) <= max tier of q's required tools}`;
tool-granular grant `A_req(q) = R(q)`, the tools in the task's published ground-truth trajectory (oracle provisioning).

**Decision order** (per call):
1. Identity check (HMAC signature, expiry, task binding); failure is final.
2. Gate A: tool in grant? (overridable)
3. Provenance: a state-changing call outside the scope (grant, or required tools) is a final denial.
4. Gate B: severity <= task-tier ceiling? (overridable)
5. Approver, on overridable failures only:
   * `deny`: refuse;
   * `task_tier`: approve if severity <= task-tier ceiling;
   * `own_tier`: approve if severity <= ceiling of the tool's own tier;
   * `tier_constrained`: refuse unknown tools and tools above the task tier; otherwise approve if severity <= ceiling.

**Outcome scoring.** AgentDojo's own `security` / `security_from_traces` and `utility` checks on the executed calls and
final state. Replay terminal text is empty; no outcome is fixed in advance.

## Attack-framing study (planned extension)

`plan` -> `live --phase pilot` -> `select` -> `live --phase confirm` -> `analyze` -> `report`.
`plan` writes the sample, seed, framings and selection rule to `attack_plan_plan.json` before any API call.
See the docstring at the top of `geaa.py`.

## Scope

Grants are provisioned from known legitimate trajectories, so the replay measures containment of presented calls under
known task requirements, not intent-to-policy translation or live-agent risk reduction.
