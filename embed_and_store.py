"""Embed each clean CVE record and upsert it into Qdrant. Re-runnable: upserts by cve_id, so running twice doesn't duplicate."""
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

    if not client.collection_exists(COLLECTION_NAME):
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
