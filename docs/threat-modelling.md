# Threat Modelling

The Threat Modelling Agent investigates OWASP-shaped attack scenarios from
gateway evidence, implemented in `backend/common/threats.py` and executed by
the `threat_model` investigator with one bounded Muse Spark elaboration call.

## Evidence analysed

- Routes: paths, methods and per-route plugins (new in the inventory join).
- Service plugins, including route-level rollup and gateway-wide plugins.
- Consumers (best-effort; outage degrades to a warning, never a failure).
- Business context: priority services escalate sensitive-operation severity.
- Not available: API specifications. Spec-dependent checks are skipped and the
  limitation is recorded on the agent record — never silently ignored.

## Scenarios

Each detector fires only when its preconditions are present in the evidence:

- BOLA: id-parameter routes with no provable object-level authorisation.
- Broken Authentication: no auth plugin on the service or its routes.
- BOPLA: state-changing routes without request validation.
- Unrestricted Consumption: no rate limiting.
- BFLA: sensitive routes without acl.
- Misconfiguration: exposed debug/internal routes.
- Inventory: services with zero routes (possible shadow APIs).
- Excessive Exposure: read routes without response filtering.
- Sensitive Operations: payment/order/admin paths with weak or missing
  controls, escalated for priority services.
- Unsafe Consumption: assessment-level limitation — upstream safety cannot be
  judged from gateway config, so it ships a dependency-review recommendation
  instead of a verdict.

## Honesty rules

- Every scenario is labelled `hypothesis: true` with preconditions, evidence
  references and non-destructive, authorization-prefixed test recommendations.
- Attack paths may only traverse evidenced relationships (shared auth plugin
  or shared path prefix); ungrounded hops the model proposes are pruned and
  the pruning is recorded.
- The agent holds one tool (`llm_threat_elaborate`) and performs no testing
  itself — destructive or otherwise. Tests are recommendations for humans.
- LLM failure keeps the deterministic scenarios and skips elaboration openly.

## Structured output

Each threat carries `threat_id`, `service`, `scenario_id`, `owasp_ref`,
`stride`, `severity_hint`, `hypothesis`, `preconditions`, `evidence_refs`,
`attack_path`, `objective`, `assets`, `business_impact`, `recommended_tests`
and `model_explanation`, alongside the legacy `category`/`title`/`basis` keys.

## Verifying

- Unit: `python -m pytest backend/tests/test_threats.py -q`.
- Synthetic estates: shop/admin/hardened scenarios in
  `backend/tests/test_orchestrator.py` cover structured output, path pruning
  and LLM-failure survival.
