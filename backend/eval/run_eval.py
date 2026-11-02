"""
===============================================================================
 File Name   : eval/run_eval.py
 Description : Model evaluation runner. Scores Muse Spark 1.3 against the
               optional fallback (or two deterministic mocks) on representative
               security-auditing tasks using reproducible judges - never
               LLM-as-judge, never a bare assertion.

                   # offline harness check (no keys, no network)
                   python backend/eval/run_eval.py --compare mock:good mock:weak

                   # live comparison (needs META_API_KEY; azure needs its
                   # endpoint/key/deployment plus META_ONLY=false)
                   python backend/eval/run_eval.py --compare meta azure

               Results print as a table and save to --out JSON. A verdict of
               "better" is only ever stated from these measured numbers, with
               the sample size shown alongside.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, router  # noqa: E402
from eval import judge  # noqa: E402

TASKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tasks.json")

AUDIT_SYSTEM = (
    "You are an autonomous API security auditor for Kong Gateway. "
    "Respond with STRICT JSON and nothing else: "
    '{"serviceName": "<name>", "policies": [{"policy_name": "<policy>", '
    '"comply": true|false, "missing_plugins": ["<plugin>"], "details": "<why>"}]}'
)

REMEDIATION_SYSTEM = (
    "You are an API security remediation expert for Kong Gateway. "
    "Respond with STRICT JSON only: an array of objects, each with exactly "
    "these keys: serviceName, policyName, issue, missingPlugin, "
    "recommendedAction, severity, owner, estimatedEffort, impact, "
    "securityStandardReference."
)

EXPLAIN_SYSTEM = (
    "You summarise audit findings for a security lead. Use only the brief "
    "given. Plain text."
)


def build_messages(task):
    marker = f"[EVAL:{task['id']}]"
    if task["kind"] == "verdict":
        service = task["service"]
        return [
            {"role": "system", "content": AUDIT_SYSTEM},
            {"role": "user", "content": (
                f"{marker}\nKong service name: {service['service_name']}\n"
                f"Enabled Kong plugins: {service['service_plugins'] or 'none'}\n"
                f"Security standards in scope: {', '.join(task['standards'])}\n\n"
                f"Organization security policy excerpts:\n{task['excerpts']}")},
        ]
    if task["kind"] == "remediation":
        return [
            {"role": "system", "content": REMEDIATION_SYSTEM},
            {"role": "user", "content": (
                f"{marker}\nAudit findings:\n"
                f"{json.dumps(task['findings'], indent=2)}\n\n"
                f"Policy excerpts:\n{task['excerpts']}")},
        ]
    return [
        {"role": "system", "content": EXPLAIN_SYSTEM},
        {"role": "user", "content": f"{marker}\nBrief:\n{task['brief']}"},
    ]


def resolve_target(spec, tasks):
    """Return (label, call) where call(task) -> (text, usage|None, model)."""
    if spec == "meta":
        if not config.META_API_KEY:
            raise SystemExit("meta needs META_API_KEY in backend/.env")
        model = config.META_MODEL

        def call(task):
            instance = router.Router()
            response = instance.run_direct(
                "meta", model, task["task"], build_messages(task),
                expect="text", max_tokens=1500)
            return response.text, response.usage, model

        return f"meta:{model}", call
    if spec == "azure":
        if config.META_ONLY:
            raise SystemExit("azure needs META_ONLY=false in backend/.env")
        for name in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
                     "AZURE_OPENAI_DEPLOYMENT_NAME"):
            if not getattr(config, name):
                raise SystemExit(f"azure needs {name} in backend/.env")
        model = config.AZURE_OPENAI_DEPLOYMENT_NAME

        def call(task):
            instance = router.Router()
            response = instance.run_direct(
                "azure", model, task["task"], build_messages(task),
                expect="text", max_tokens=1500)
            return response.text, response.usage, model

        return f"azure:{model}", call
    if spec in ("mock:good", "mock:weak"):
        key = "ideal" if spec == "mock:good" else "flawed"
        by_id = {t["id"]: t for t in tasks}

        def call(task):
            exemplar = by_id[task["id"]][key]
            text = exemplar if isinstance(exemplar, str) else json.dumps(exemplar)
            return text, None, spec

        return spec, call
    raise SystemExit(f"Unknown target '{spec}'. Use meta, azure, mock:good, mock:weak.")


def run_suite(label, call, tasks):
    import time
    results = []
    for task in tasks:
        started = time.monotonic()
        try:
            text, usage, model = call(task)
            verdict = judge.score(task, text)
            error = ""
        except Exception as exc:  # noqa: BLE001 - failures score zero
            text, usage, model, error = "", None, label, str(exc)[:300]
            verdict = {"checks": {"ran": False}, "passed": False, "score": 0.0}
        results.append({
            "id": task["id"], "kind": task["kind"], "model": model,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "usage": usage, "error": error, **verdict,
        })
    passed = sum(1 for r in results if r["passed"])
    return {
        "label": label,
        "tasks": results,
        "summary": {
            "total": len(results),
            "passed": passed,
            "avg_score": round(sum(r["score"] for r in results) / len(results), 3)
            if results else 0.0,
        },
    }


def print_table(report):
    suites = report["suites"]
    header = f"{'task':<24}" + "".join(f"{s['label'][:22]:>24}" for s in suites)
    print(header)
    print("-" * len(header))
    for i, task in enumerate(report["task_ids"]):
        row = f"{task:<24}"
        for suite in suites:
            result = suite["tasks"][i]
            mark = "PASS" if result["passed"] else "FAIL"
            row += f"{mark + ' ' + str(result['score']):>24}"
        print(row)
    print("-" * len(header))
    row = f"{'passed':<24}"
    for suite in suites:
        summary = suite["summary"]
        cell = f"{summary['passed']}/{summary['total']} avg {summary['avg_score']:.3f}"
        row += f"{cell:>24}"
    print(row)
    print(f"\nn={len(report['task_ids'])} illustrative tasks; "
          f"treat deltas as indicative, not significant.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate providers on audit tasks.")
    parser.add_argument("--compare", nargs="+", default=["mock:good", "mock:weak"],
                        help="Targets: meta, azure, mock:good, mock:weak.")
    parser.add_argument("--tasks", default=TASKS_PATH)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    with open(args.tasks, encoding="utf-8") as handle:
        tasks = json.load(handle)
    suites = []
    for spec in args.compare:
        label, call = resolve_target(spec, tasks)
        print(f"running {label} over {len(tasks)} tasks...")
        suites.append(run_suite(label, call, tasks))
    report = {"task_ids": [t["id"] for t in tasks], "suites": suites}
    print_table(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"wrote {args.out}")
    return report


if __name__ == "__main__":
    main()
