---
name: scope-check
description: Check a proposed change or feature idea against SecAdvisor's explicit in-scope/out-of-scope list before building it. Use when the user proposes adding a feature, or before starting any non-trivial new piece of work on this project.
---

Compare the proposed work against SecAdvisor's build plan:

**In scope:**
1. Ingest a static snapshot of a few hundred CVE/advisory records into a vector DB (Qdrant).
2. Free-text Q&A with retrieval-grounded, cited answers (LangChain + Groq/Gemini).
3. "Does my stack have exposure?" mode — list techs, get matching advisories ranked by severity.
4. A thin Streamlit UI (two tabs: Q&A, stack exposure).
5. Deploy to a free public URL (Hugging Face Spaces).

**Explicitly out of scope:**
- Real-time/scheduled CVE feed syncing (static snapshot only).
- User accounts, auth, multi-user.
- A full OWASP-LLM security scanner.
- Agentic actions / tool-calling (RAG only).
- Fine-tuning anything.
- Any paid/card-based cloud service — zero-spend stack only.

If the proposed work matches an in-scope item, proceed normally. If it falls outside the list (or expands an in-scope item significantly — e.g. "let's also add live feed syncing"), say so explicitly before implementing: name which out-of-scope item it resembles, and ask whether to proceed anyway, defer it, or cut something else to stay on the two-weekend timeline. The build plan's own rule: if behind schedule, cut scope — never extend the timeline.
