"""Tests for the evaluation harness. Fully offline: judges run over canned
responses and the mock comparison runs through the real runner entry point."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import judge, run_eval  # noqa: E402


def _tasks():
    with open(run_eval.TASKS_PATH, encoding="utf-8") as handle:
        return {t["id"]: t for t in json.load(handle)}


def test_ideal_exemplars_pass_every_judge():
    tasks = _tasks()
    for task_id, task in tasks.items():
        text = task["ideal"]
        text = text if isinstance(text, str) else json.dumps(text)
        verdict = judge.score(task, text)
        assert verdict["passed"] is True, (task_id, verdict["checks"])


def test_flawed_exemplars_fail_expected_checks():
    tasks = _tasks()
    verdict = judge.score(tasks["verdict-auth-missing"],
                          json.dumps(tasks["verdict-auth-missing"]["flawed"]))
    assert verdict["checks"]["Auth:verdict"] is False
    halluc = judge.score(tasks["verdict-no-hallucination"],
                         json.dumps(tasks["verdict-no-hallucination"]["flawed"]))
    assert halluc["checks"]["Auth:no_contradiction"] is False
    remedy = judge.score(tasks["remediation-basic"],
                         json.dumps(tasks["remediation-basic"]["flawed"]))
    assert remedy["checks"]["all_keys"] is False
    batch = judge.score(tasks["remediation-batch"],
                        json.dumps(tasks["remediation-batch"]["flawed"]))
    assert batch["checks"]["item_count"] is False
    grounded = judge.score(tasks["explanation-grounding"],
                           tasks["explanation-grounding"]["flawed"])
    assert grounded["checks"]["required_terms"] is False
    assert grounded["checks"]["forbidden_terms"] is False


def test_mock_compare_measures_a_gap(tmp_path, capsys):
    out = str(tmp_path / "report.json")
    report = run_eval.main(["--compare", "mock:good", "mock:weak", "--out", out])
    good, weak = (s["summary"] for s in report["suites"])
    assert good["passed"] == 6 and good["avg_score"] == 1.0
    assert weak["passed"] < good["passed"]
    assert weak["avg_score"] < good["avg_score"]
    assert os.path.exists(out)
    assert "n=6" in capsys.readouterr().out
