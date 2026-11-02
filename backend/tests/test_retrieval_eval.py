"""Gate on retrieval relevance over the curated dataset.

Runs the offline (in-memory) store over the real corpus files. A failure
means the corpus and the dataset disagree - update the tasks alongside any
corpus change instead of weakening this gate.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import run_retrieval_eval  # noqa: E402


def test_retrieval_dataset_is_well_formed():
    with open(run_retrieval_eval.TASKS_PATH, encoding="utf-8") as handle:
        tasks = json.load(handle)
    assert len(tasks) >= 10
    for task in tasks:
        assert task["query"] and task["expected_sources"]
        assert int(task.get("top_k", 3)) > 0


def test_offline_retrieval_hits_every_task():
    with open(run_retrieval_eval.TASKS_PATH, encoding="utf-8") as handle:
        tasks = json.load(handle)
    summary = run_retrieval_eval.run(tasks, run_retrieval_eval.FakeStore())
    assert summary["hit_rate"] == 1.0, summary["rows"]
    assert summary["mrr"] >= 0.9, summary["rows"]
