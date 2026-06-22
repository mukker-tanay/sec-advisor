"""Given a list of techs, find matching advisories per tech, dedupe, and rank by severity.

This is a structured lookup, not a semantic question -- "does my stack include X" should
match against the literal affected_products field (vendor/product strings), not embedding
similarity over the description text. An earlier version used vector similarity here and it
produced false positives (e.g. "openssl 3.0" matching unrelated 1999 CVEs that just had
generically similar wording) because semantic similarity isn't the right tool for an exact
membership check. Plain substring matching is simpler, correct, and needs no LLM call.
"""
import json
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
RECORDS_PATH = Path("data/clean_records.jsonl")


def load_records() -> list[dict]:
    return [json.loads(line) for line in RECORDS_PATH.read_text(encoding="utf-8").splitlines() if line]


def check_stack_exposure(techs: list[str], records: list[dict]) -> list[dict]:
    matches_by_cve = {}
    techs_lower = [t.lower() for t in techs]

    for record in records:
        products_lower = [p.lower() for p in record["affected_products"]]
        matched = [
            tech for tech, tech_lower in zip(techs, techs_lower)
            if any(tech_lower in product for product in products_lower)
        ]
        if matched:
            matches_by_cve[record["cve_id"]] = {"record": record, "matched_techs": set(matched)}

    ranked = sorted(
        matches_by_cve.values(),
        key=lambda m: (
            SEVERITY_ORDER.get(m["record"]["severity"], 0),
            m["record"]["cvss_score"] or 0,
        ),
        reverse=True,
    )

    return [
        {
            "cve_id": m["record"]["cve_id"],
            "matched_techs": sorted(m["matched_techs"]),
            "severity": m["record"]["severity"],
            "cvss_score": m["record"]["cvss_score"],
            "description": m["record"]["description"],
            "references": m["record"]["references"][:3],
        }
        for m in ranked
    ]


def main():
    records = load_records()
    techs = ["sendmail", "sunos", "openssl 3.0"]
    results = check_stack_exposure(techs, records)

    print(f"Checked: {techs}\n")
    if not results:
        print("No known advisories matched.")
    for r in results:
        print(f"[{r['severity']} {r['cvss_score']}] {r['cve_id']} (matched: {', '.join(r['matched_techs'])})")
        print(f"  {r['description'][:100]}")


if __name__ == "__main__":
    main()
