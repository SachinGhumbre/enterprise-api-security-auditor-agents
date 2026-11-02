"""
===============================================================================
 File Name   : eval/run_retrieval_eval.py
 Description : Retrieval relevance runner. Scores policy retrieval on the
               representative dataset in retrieval_tasks.json using hit@k and
               MRR - never LLM-as-judge.

                   # offline (in-memory store over the real corpus files)
                   python backend/eval/run_retrieval_eval.py --store fake

                   # live Redis Stack index (needs ingest first)
                   python backend/eval/run_retrieval_eval.py --store redis

               Results print as a table and save to --out JSON. A claim that
               retrieval "works" is only ever stated from these measured
               numbers, with the store and sample size shown alongside.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402
from common import embeddings as embedding_mod  # noqa: E402
from common import vector_store  # noqa: E402
from rag.knowledge_ingestor import chunk_text, iter_knowledge_files  # noqa: E402

TASKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "retrieval_tasks.json")
FAKE_DIMENSIONS = 384


class FakeStore:
    """In-memory retrieval over the real corpus: chunking, metadata and
    filtering run the production code; only the KNN index is replaced by a
    brute-force cosine rank with deterministic local embeddings."""

    def __init__(self, knowledge_dir=None):
        self.chunks = []
        root = knowledge_dir or config.KNOWLEDGE_DIR
        for file_path in iter_knowledge_files(root):
            filename = os.path.relpath(file_path, root).replace("\\", "/")
            with open(file_path, "r", encoding="utf-8",
                      errors="replace") as handle:
                content = handle.read()
            header = vector_store.parse_doc_header(content)
            for position, chunk in enumerate(chunk_text(content)):
                self.chunks.append({
                    "id": f"fake:{filename}:{position}",
                    "content": chunk,
                    "source": filename,
                    "metadata": {
                        "filename": filename,
                        "policy_version": (
                            header.get("policy_version")
                            or vector_store.derive_version(content)),
                        "category": (
                            header.get("category") or
                            vector_store.derive_category(filename, content)),
                        "applies_to": header.get("applies_to") or "all",
                        "effective_date": header.get("effective_date"),
                    },
                    "vector": embedding_mod._local_embedding(
                        chunk, FAKE_DIMENSIONS),
                })
        self.manifest = {}
        for chunk in self.chunks:
            filename = chunk["source"]
            self.manifest.setdefault(filename, {"policy_version": chunk[
                "metadata"]["policy_version"]})

    def search(self, query, top_k=3, filters=None):
        scored = []
        needle = embedding_mod._local_embedding(query, FAKE_DIMENSIONS)
        for chunk in self.chunks:
            cosine = float(np.dot(needle, chunk["vector"]))
            scored.append((cosine, chunk))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        hits = [{"id": c["id"], "content": c["content"],
                 "source": c["source"], "metadata": dict(c["metadata"]),
                 "score": round(s, 4)} for s, c in scored]
        kept = vector_store.apply_filters(
            hits, filters, manifest=self.manifest)
        return kept[:top_k]


class RedisStore:
    """The production RediSearch index (ingest first)."""

    def search(self, query, top_k=3, filters=None):
        return vector_store.search(query, top_k=top_k, filters=filters)


def run(tasks, store):
    rows = []
    for task in tasks:
        top_k = int(task.get("top_k", 3))
        hits = store.search(task["query"], top_k=top_k,
                            filters=task.get("filters"))
        sources = [h.get("source") for h in hits]
        expected = set(task.get("expected_sources", []))
        rank = next((i + 1 for i, source in enumerate(sources)
                     if source in expected), None)
        rows.append({"id": task["id"], "hit": rank is not None,
                     "rank": rank, "sources": sources})
    hits = sum(1 for row in rows if row["hit"])
    mrr = (sum(1.0 / row["rank"] for row in rows if row["rank"])
           / len(rows) if rows else 0.0)
    return {"tasks": len(rows), "hits": hits,
            "hit_rate": round(hits / len(rows), 3) if rows else 0.0,
            "mrr": round(mrr, 3), "rows": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Retrieval relevance eval.")
    parser.add_argument("--store", choices=("fake", "redis"), default="fake")
    parser.add_argument("--knowledge-dir", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    with open(TASKS_PATH, encoding="utf-8") as handle:
        tasks = json.load(handle)
    if args.store == "redis":
        store = RedisStore()
        store_name = f"redis ({config.INDEX_NAME})"
    else:
        store = FakeStore(knowledge_dir=args.knowledge_dir)
        store_name = f"fake ({len(store.chunks)} chunks)"

    summary = run(tasks, store)
    summary["store"] = store_name
    print(f"store: {store_name} | tasks: {summary['tasks']} | "
          f"hit_rate: {summary['hit_rate']} | mrr: {summary['mrr']}")
    for row in summary["rows"]:
        mark = "HIT " if row["hit"] else "MISS"
        print(f"  [{mark}] {row['id']}: rank={row['rank']} "
              f"sources={row['sources']}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
        print(f"saved {args.out}")
    return summary


if __name__ == "__main__":
    main()
