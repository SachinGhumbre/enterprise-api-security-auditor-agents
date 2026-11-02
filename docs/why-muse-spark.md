# Why Muse Spark 1.3 Is Central

Six jobs in this system require judgment over messy context, and all six
route to Muse Spark 1.3 through one enforced routing table — no agent
picks its own model, and an empty model id refuses to call rather than
falling back to a default:

1. **Security investigation** — verdicts per service from plugins plus
   retrieved policy excerpts.
2. **Evidence correlation** — reconciling what parallel agents found.
3. **Threat modelling** — attack scenarios with preconditions from
   inventory and business context.
4. **Risk reasoning** — explaining why the ranked register is ranked
   that way (the scores themselves are deterministic).
5. **Remediation planning** — actions, then structured change prose
   (rationale, impact, breaking changes, validation steps).
6. **Executive explanation** — board-ready narrative over verified
   findings only.

The division of labour is deliberate: Spark reasons and explains;
deterministic code verifies claims against Kong inventory, computes
risk, enforces budgets and approvals, and executes changes. That is why
the system can show its work — every model output it acts on is checked,
cited, or quarantined by something that isn't a model.

Operationally: `META_MODEL=muse-spark-1.3` is the explicit default,
`META_ONLY=true` forbids non-Meta reasoning providers, every call is
logged with model, task, latency and usage (never bodies), and the
dashboard's Model Analytics page renders the routing table and the live
call log for anyone to inspect.
