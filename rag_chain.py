"""LangChain RAG chain: query rewriting -> retrieve with Qdrant pre-filtering -> grounded, cited answer or explicit refusal."""
import json
import os
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_qdrant import QdrantVectorStore
from qdrant_client.http import models as qdrant_models

load_dotenv()

COLLECTION_NAME = "cve_advisories"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
TOP_K = 5
MIN_SCORE = 0.2

# 1. Query Rewriter Prompt: Extracts structured filters from natural language
REWRITER_PROMPT = ChatPromptTemplate.from_template(
    """Analyze the security question below and extract specific software components (vendor and/or product name) if the user is asking about a specific technology.

Output a JSON object with:
- "vendor": The name of the vendor (e.g. "apache", "sendmail", "microsoft") or null if not specified.
- "product": The name of the product (e.g. "http_server", "windows") or null if not specified.

If the question is general (e.g. "what is a CVE?", "how to secure routers?", "tell me about buffer overflows in general") or a system command/jailbreak, set both "vendor" and "product" to null.

Question: {question}

JSON output:"""
)

# 2. Main grounded QA Prompt
PROMPT = ChatPromptTemplate.from_template(
    """You are a security advisory assistant. Answer the question using ONLY the
retrieved CVE records below. Cite the CVE ID(s) you used in your answer.

If none of the retrieved records actually address the question -- even if they
were retrieved -- say plainly "I don't have an advisory on that" instead of
guessing or extrapolating. Do not use outside knowledge.

Retrieved CVE records:
{context}

Question: {question}

Answer:"""
)


def get_vector_store() -> QdrantVectorStore:
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL,
        model_kwargs={"local_files_only": True}
    )
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_path = os.environ.get("QDRANT_PATH", "data/qdrant_db")
    
    if qdrant_url:
        return QdrantVectorStore.from_existing_collection(
            embedding=embeddings,
            collection_name=COLLECTION_NAME,
            url=qdrant_url,
        )
    else:
        return QdrantVectorStore.from_existing_collection(
            embedding=embeddings,
            collection_name=COLLECTION_NAME,
            path=qdrant_path,
        )


def format_context(docs_with_scores) -> str:
    lines = []
    for doc, score in docs_with_scores:
        p = doc.metadata
        lines.append(
            f"{p['cve_id']} (relevance {score:.2f}): {p['description']} "
            f"Severity: {p['severity']}. Affected: {', '.join(p['affected_products']) or 'unspecified'}."
        )
    return "\n".join(lines)


def answer_question(question: str, vector_store: QdrantVectorStore, llm: ChatGroq) -> tuple[str, list[dict]]:
    """Returns (answer, sources).
    First rewrites query to extract parameters, builds Qdrant filters, retrieves, and prompts.
    """
    # Phase 3: Query Rewriting / Parameter Extraction
    vendor, product = None, None
    try:
        rewriter_chain = REWRITER_PROMPT | llm.bind(response_format={"type": "json_object"})
        rewriter_res = rewriter_chain.invoke({"question": question})
        extracted = json.loads(rewriter_res.content)
        vendor = extracted.get("vendor")
        product = extracted.get("product")
    except Exception as e:
        # Graceful fallback: do not crash on LLM parsing issues
        pass

    # Phase 3: Build Qdrant filter based on extracted terms
    query_filter = None
    if vendor or product:
        conditions = []
        if vendor:
            conditions.append(qdrant_models.FieldCondition(
                key="metadata.affected_products",
                match=qdrant_models.MatchText(text=vendor)
            ))
        if product:
            conditions.append(qdrant_models.FieldCondition(
                key="metadata.affected_products",
                match=qdrant_models.MatchText(text=product)
            ))
        query_filter = qdrant_models.Filter(must=conditions)

    # Retrieval using Qdrant pre-filtering
    results = vector_store.similarity_search_with_score(question, k=TOP_K, filter=query_filter)
    relevant = [(doc, score) for doc, score in results if score >= MIN_SCORE]

    # Fallback to unfiltered vector search if strict pre-filtering retrieved nothing
    # (e.g. if the software tool is mentioned in description but missing in metadata CPEs)
    if not relevant and query_filter is not None:
        results = vector_store.similarity_search_with_score(question, k=TOP_K)
        relevant = [(doc, score) for doc, score in results if score >= MIN_SCORE]

    if not relevant:
        return "I don't have an advisory on that.", []

    context = format_context(relevant)
    chain = PROMPT | llm
    response = chain.invoke({"context": context, "question": question})
    sources = [doc.metadata for doc, _ in relevant]
    return response.content, sources


def get_llm() -> ChatGroq:
    return ChatGroq(model="llama-3.1-8b-instant", api_key=os.environ["GROQ_API_KEY"])


def main():
    vector_store = get_vector_store()
    llm = get_llm()

    test_questions = [
        "Is there a known issue with the debug command in Sendmail?",
        "Is there a vulnerability affecting OpenSSL 3.0?",
    ]
    for q in test_questions:
        answer, sources = answer_question(q, vector_store, llm)
        print(f"\nQ: {q}")
        print(f"A: {answer}")
        print(f"Sources: {[s['cve_id'] for s in sources]}")


if __name__ == "__main__":
    main()
