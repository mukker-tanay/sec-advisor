---
title: SecAdvisor
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
pinned: false
app_port: 7860
---

# 🛡️ SecAdvisor

A RAG security-advisory assistant that answers CVE questions with cited sources, and refuses honestly when it doesn't know. **[Live demo](https://huggingface.co/spaces/mukker-tanay/Sec-Advisor)**

SecAdvisor is a RAG (Retrieval-Augmented Generation) security advisory assistant. It ingests, validates, indexes, and queries CVE (Common Vulnerabilities and Exposures) records using a hybrid-retrieval pipeline.

It's a demo-scale CV project, not a production system — built to practice and show real RAG engineering: a resilient ingestion pipeline, schema validation against API drift, structured query rewriting to improve retrieval, and a metric-driven evaluation harness rather than just eyeballing outputs.

---

## 🏗️ Architecture

The system consists of three main components:
1. **Resilient Ingestion Pipeline:** 
   - [fetch_snapshot.py](fetch_snapshot.py) paginates and fetches raw CVE records from the NVD API. It features **exponential backoff with jitter** to handle rate-limiting and a **delta-sync** mode to incrementally fetch updates.
   - [parse_records.py](parse_records.py) cleans and validates records using a strict **Pydantic v2 schema**, gracefully catching schema drifts without crashing.
   - [embed_and_store.py](embed_and_store.py) recreates the Qdrant collection fresh from `data/clean_records.jsonl` on every run (rather than incrementally upserting), so it always exactly matches the current source data with no stale leftovers from an earlier seed.
2. **Hybrid RAG Retriever:**
   - [rag_chain.py](rag_chain.py) rewrites raw natural language questions via Groq (Llama-3.1-8b) to extract structured vendor/product entities.
   - Applies pre-filtering on Qdrant payloads, ensuring similarity search matches the target technology.
   - Restricts LLM answering strictly to the retrieved context and cites CVE IDs. Bypasses LLM calls entirely below a `MIN_SCORE = 0.2` similarity threshold to save token costs and prevent hallucinations.
3. **Automated Evaluation Harness:**
   - [evaluate.py](evaluate.py) runs an automated **LLM-as-a-judge** test suite grading groundedness, refusal accuracy (out-of-scope), and jailbreak/prompt injection safety.

---

## 📈 Performance Metrics

Current result on the 13-case `evaluate.py` suite (5 grounded questions, 5 out-of-domain refusals, 3 prompt-injection attempts), run against the live recent-CVE dataset with a separate judge model (`llama-3.3-70b-versatile`) grading the generator model's (`llama-3.1-8b-instant`) answers:

| Metric | Result |
| :--- | :--- |
| **Grounded Accuracy** | 100% (5/5) |
| **Refusal/Safety Accuracy** | 100% (8/8) |
| **Overall Accuracy** | 100% (13/13) |
| **Average Latency** | ~4.0s |

This is the result on a small, fixed test suite — it means the system handles these 13 specific cases correctly, not that grounding or injection resistance are guaranteed in general. See [What this does NOT do](#what-this-does-not-do) below, and [DECISIONS.md](DECISIONS.md) for how this number changed as the test suite, judge model, and prompt were each fixed in turn (an earlier version of this table showed a misleadingly low 40% grounded accuracy caused by an unreliable same-model judge, not an actual regression).

---

## What this does NOT do

- **The dataset is small and recency-windowed, not comprehensive.** The default fetch pulls NVD records published in roughly the last 120 days (NVD's own cap on a single date-range query), not the full CVE history. It's a demo-scale snapshot for proving the RAG pipeline works, not a complete vulnerability database — don't expect it to know about a CVE from several years ago unless a sync has specifically pulled it in.
- **No live syncing in practice yet.** A `--sync` delta-fetch mode exists in `fetch_snapshot.py` (and is designed to only ever add CVEs, never prune old ones), but nothing currently triggers it automatically — every deployed instance runs off a snapshot taken at build time. A scheduled job to actually run this on a cadence is planned, not yet wired up.
- **No authentication, no multi-user state.** It's a single-shared demo, not a product.
- **The prompt-injection resistance is tested against a small, fixed suite, not proven unbreakable.** `evaluate.py` currently passes all 13 of its cases, including a role-changing jailbreak prompt — but that means it handles these specific known attempts, not that it resists prompt injection in general. Treat any security claim here as "tested against these cases," not "guaranteed."

---

## 🚀 Running Locally

### 1. Prerequisites
- `GROQ_API_KEY` (required) and optional `NVD_API_KEY` (raises NVD's rate limit) in a `.env` file
- `uv` for python environment management

### 2. Setup
By default, Qdrant runs as an embedded on-disk store at `data/qdrant_db` -- no separate server needed. If you'd rather run a real Qdrant server (e.g. matching a Docker-based deploy), set `QDRANT_URL=http://localhost:6333` in `.env` and start it with:
```bash
docker run -p 6333:6333 -p 6334:6334 -v $(pwd)/data/qdrant_storage:/qdrant/storage qdrant/qdrant
```

Install python dependencies:
```bash
uv sync
```

### 3. Execution
Fetch and ingest a fresh snapshot (recent CVEs, last ~120 days by default):
```bash
uv run python fetch_snapshot.py --limit 1000
uv run python parse_records.py
uv run python embed_and_store.py
```

Run the automated evaluations:
```bash
uv run python evaluate.py
```

Launch the Streamlit dashboard:
```bash
uv run streamlit run app.py
```
