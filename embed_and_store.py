"""Embed each clean CVE record and load it into Qdrant. Re-runnable: recreates the collection
fresh from clean_records.jsonl every run, so it always exactly matches the current source data
(no stale leftovers from an earlier seed, no manual cleanup needed)."""
import json
import os
from pathlib import Path
from dotenv import load_dotenv

from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

load_dotenv()

INPUT_PATH = Path("data/clean_records.jsonl")
COLLECTION_NAME = "cve_advisories"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384  # native output size of all-MiniLM-L6-v2


def record_to_text(record: dict) -> str:
    """Build the text we embed -- one chunk per CVE, not split further."""
    products = ", ".join(record["affected_products"]) or "unspecified"
    severity = record["severity"] or "unknown"
    return (
        f"{record['cve_id']}: {record['description']} "
        f"Severity: {severity} (CVSS {record['cvss_score']}). "
        f"Affected: {products}."
    )


def cve_id_to_point_id(cve_id: str) -> int:
    """Qdrant point IDs must be int or UUID, not arbitrary strings -- derive a stable int from the CVE ID."""
    import hashlib
    return int(hashlib.sha256(cve_id.encode()).hexdigest()[:16], 16)


def main():
    records = [json.loads(line) for line in INPUT_PATH.read_text(encoding="utf-8").splitlines() if line]

    model = SentenceTransformer(EMBEDDING_MODEL)
    
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_path = os.environ.get("QDRANT_PATH", "data/qdrant_db")
    
    if qdrant_url:
        client = QdrantClient(url=qdrant_url)
    else:
        client = QdrantClient(path=qdrant_path)

    # clean_records.jsonl is already the complete, deduplicated dataset on every run
    # (fetch_snapshot.py merges by cve_id into the raw snapshot, and parse_records.py
    # rebuilds clean_records.jsonl fully from that each time). So the collection should be
    # recreated fresh from it rather than upserted onto whatever was there before --
    # otherwise records removed from the source (e.g. an earlier toy-data seed) linger
    # in Qdrant forever even though they're no longer in clean_records.jsonl.
    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
    )

    texts = [record_to_text(r) for r in records]
    embeddings = model.encode(texts, show_progress_bar=True)

    points = [
        PointStruct(
            id=cve_id_to_point_id(record["cve_id"]),
            vector=embedding.tolist(),
            # page_content/metadata shape matches what LangChain's QdrantVectorStore expects on read.
            payload={"page_content": text, "metadata": record},
        )
        for record, embedding, text in zip(records, embeddings, texts)
    ]
    client.upsert(collection_name=COLLECTION_NAME, points=points)

    print(f"Upserted {len(points)} records into '{COLLECTION_NAME}'.")


if __name__ == "__main__":
    main()
