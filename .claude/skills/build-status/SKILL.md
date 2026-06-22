---
name: build-status
description: Report progress against SecAdvisor's two-weekend build order (Steps 1-6). Use when the user asks "where are we", "what's left", or wants a status check on this project.
---

Check the repo for evidence of each build step and report which are done, in progress, or not started. Don't take the user's word for prior progress — verify against the filesystem/code.

1. **Data** — a script that downloads/parses an NVD CVE snapshot into clean `{cve_id, description, severity, affected_products, remediation, published_date}` records.
2. **Embed + store** — Qdrant running (check for docker-compose or connection code) and an ingestion script that embeds records with sentence-transformers and upserts them.
3. **Retrieval + generation** — a LangChain RAG chain (question → embed → retrieve → prompt → LLM) that cites CVE IDs and refuses when retrieval is empty. Check specifically whether the refusal behavior has been tested, not just coded — this is called out as the most important feature to verify.
4. **Stack exposure mode** — multi-tech lookup that retrieves per tech, dedupes, and ranks by severity.
5. **Streamlit UI** — two tabs (Q&A, stack exposure) showing retrieved sources alongside answers.
6. **Deploy + README** — pushed to Hugging Face Spaces with a public URL, and a README following the structure in the build plan (problem, architecture diagram, honest example/metric, explicit limits, stack, local run instructions).

Report as a short checklist (done / in progress / not started) with one-line notes on what's missing for any incomplete step. End with the single next concrete action per the build order — don't suggest skipping ahead.
