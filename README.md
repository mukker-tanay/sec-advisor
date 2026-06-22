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

SecAdvisor is an enterprise-grade prototype for a RAG-based (Retrieval-Augmented Generation) security advisory agent. It ingests, validates, indexes, and queries CVE (Common Vulnerabilities and Exposures) records using a hybrid-retrieval pipeline.

The project is designed to demonstrates **production-grade engineering principles**—including ingestion pipeline resilience, schema drift validation, structured query rewriting, and metric-driven evaluations.

---

## 🏗️ Architecture

The system consists of three main components:
1. **Resilient Ingestion Pipeline:** 
   - [fetch_snapshot.py](fetch_snapshot.py) paginates and fetches raw CVE records from the NVD API. It features **exponential backoff with jitter** to handle rate-limiting and a **delta-sync** mode to incrementally fetch updates.
   - [parse_records.py](parse_records.py) cleans and validates records using a strict **Pydantic v2 schema**, gracefully catching schema drifts without crashing.
   - [embed_and_store.py](embed_and_store.py) hashes the CVE ID to derive a stable integer ID for idempotent Qdrant vector store indexing.
2. **Hybrid RAG Retriever:**
   - [rag_chain.py](rag_chain.py) rewrites raw natural language questions via Groq (Llama-3.1-8b) to extract structured vendor/product entities.
   - Applies pre-filtering on Qdrant payloads, ensuring similarity search matches the target technology.
   - Restricts LLM answering strictly to the retrieved context and cites CVE IDs. Bypasses LLM calls entirely below a `MIN_SCORE = 0.2` similarity threshold to save token costs and prevent hallucinations.
3. **Automated Evaluation Harness:**
   - [evaluate.py](evaluate.py) runs an automated **LLM-as-a-judge** test suite grading groundedness, refusal accuracy (out-of-scope), and jailbreak/prompt injection safety.

---

## 📈 Performance Metrics

Adding structured query-rewriting and payload pre-filtering dramatically improved system accuracy:

| Metric | Baseline RAG | Upgraded Hybrid RAG | Improvement |
| :--- | :--- | :--- | :--- |
| **Grounded Accuracy** | 60.0% | **80.0%** | **+20.0%** |
| **Refusal/Safety Accuracy** | 75.0% | **87.5%** | **+12.5%** |
| **Overall Accuracy** | 69.2% | **84.6%** | **+15.4%** |
| **Average Latency** | 1.88s | 3.12s | +1.24s (latency trade-off) |

*Detailed architectural trade-offs and decision logs are documented in [DECISIONS.md](DECISIONS.md).*

---

## 🚀 Running Locally

### 1. Prerequisites
- Docker (for Qdrant)
- python-dotenv (`GROQ_API_KEY` and optional `NVD_API_KEY`)
- `uv` for python environment management

### 2. Setup
Start the local Qdrant container:
```bash
docker run -p 6333:6333 -p 6334:6334 -v $(pwd)/data/qdrant_storage:/qdrant/storage qdrant/qdrant
```

Install python dependencies:
```bash
uv sync
```

### 3. Execution
Fetch and ingest the database (1000 CVE sample):
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
