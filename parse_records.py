"""Flatten the raw NVD snapshot into one clean record per CVE with Pydantic validation."""
import json
import logging
from typing import List, Optional
from pathlib import Path
from pydantic import BaseModel, Field, ValidationError

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

INPUT_PATH = Path("data/raw_nvd_snapshot.json")
OUTPUT_PATH = Path("data/clean_records.jsonl")

# Prefer the newest CVSS version available; fall back to older ones.
CVSS_METRIC_PRIORITY = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]


class CveRecord(BaseModel):
    """Pydantic schema representing our clean internal CVE model.
    Guards against schema drift from the external NVD API.
    """
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    published_date: Optional[str] = None
    last_modified: Optional[str] = None


def extract_severity(metrics: dict) -> tuple[str | None, float | None]:
    for key in CVSS_METRIC_PRIORITY:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        severity = entry.get("baseSeverity") or entry.get("cvssData", {}).get("baseSeverity")
        score = entry.get("cvssData", {}).get("baseScore")
        return severity, score
    return None, None


def extract_affected_products(configurations: list) -> list[str]:
    products = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    products.add(f"{vendor} {product}")
    return sorted(products)


def extract_description(descriptions: list) -> str | None:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def parse_record(cve: dict) -> dict | None:
    cve_id = cve.get("id")
    description = extract_description(cve.get("descriptions", []))
    if not cve_id or not description:
        log.warning("Skipping record with missing id/description: %s", cve.get("id"))
        return None

    severity, cvss_score = extract_severity(cve.get("metrics", {}))
    cwe_ids = sorted({
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cwe_ids": cwe_ids,
        "affected_products": extract_affected_products(cve.get("configurations", [])),
        "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
        "published_date": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def main():
    if not INPUT_PATH.exists():
        log.error("Input file %s does not exist. Please run fetch_snapshot.py first.", INPUT_PATH)
        return

    raw = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    records = []
    skipped_validation = 0
    
    for entry in raw.get("vulnerabilities", []):
        parsed = parse_record(entry.get("cve", {}))
        if parsed:
            try:
                # Enforce schema validation
                validated = CveRecord(**parsed)
                records.append(validated.model_dump())
            except ValidationError as e:
                log.warning("Validation failed for record %s. Skipping. Error: %s", parsed.get("cve_id"), e)
                skipped_validation += 1

    OUTPUT_PATH.write_text(
        "\n".join(json.dumps(r) for r in records),
        encoding="utf-8",
    )
    print(f"Parsed {len(records)}/{len(raw.get('vulnerabilities', []))} records (Skipped validation: {skipped_validation}) -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
