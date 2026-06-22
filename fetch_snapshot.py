"""Resilient, paginated fetch of NVD CVE data. Supports rate-limit backoff and delta-syncing."""
import argparse
import datetime
import json
import logging
import os
import random
import time
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_LIMIT = 5000
RESULTS_PER_PAGE = 500
OUTPUT_PATH = Path("data/raw_nvd_snapshot.json")
CLEAN_RECORDS_PATH = Path("data/clean_records.jsonl")


def get_last_modified_timestamp() -> str | None:
    """Scan existing clean records to find the latest last_modified timestamp for delta sync."""
    if not CLEAN_RECORDS_PATH.exists():
        return None
    
    latest_dt = None
    try:
        with open(CLEAN_RECORDS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                # Fall back to published_date if last_modified is missing
                mod_str = record.get("last_modified") or record.get("published_date")
                if mod_str:
                    # NVD dates look like "2026-06-19T21:30:52" or with offset/Z
                    # Standardize parse to compare
                    dt_str = mod_str.replace("Z", "").split(".")[0]
                    try:
                        dt = datetime.datetime.fromisoformat(dt_str)
                        if latest_dt is None or dt > latest_dt:
                            latest_dt = dt
                    except ValueError:
                        continue
    except Exception as e:
        log.warning("Could not parse existing clean records for sync date: %s", e)
    
    if latest_dt:
        # Format back to NVD API expectations
        return latest_dt.isoformat()
    return None


def fetch_page_with_retry(params: dict, headers: dict, max_retries: int = 5) -> dict:
    """Fetch a single page of CVEs with exponential backoff and jitter for rate-limit safety."""
    base_sleep = 6.0  # NVD without API key rate limits to 5 requests per 30s (~6s per request)
    if "apiKey" in headers or os.environ.get("NVD_API_KEY"):
        base_sleep = 0.6  # NVD with API key allows 50 requests per 30s (~0.6s per request)

    for attempt in range(max_retries):
        try:
            log.info("Fetching startIndex=%s (attempt %d/%d)...", params.get("startIndex", 0), attempt + 1, max_retries)
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                # Success: sleep briefly to be a good citizen before returning
                time.sleep(base_sleep * 0.5)
                return response.json()
            
            if response.status_code in [403, 429, 503]:
                sleep_time = base_sleep * (2 ** attempt) + random.uniform(0, 2)
                log.warning("Received status %d (Rate limited or Unavailable). Sleeping for %.2fs...", response.status_code, sleep_time)
                time.sleep(sleep_time)
            else:
                response.raise_for_status()
                
        except requests.RequestException as e:
            sleep_time = base_sleep * (2 ** attempt) + random.uniform(0, 2)
            log.warning("Network error: %s. Retrying in %.2fs...", e, sleep_time)
            time.sleep(sleep_time)
            
    raise RuntimeError(f"Failed to fetch from NVD API after {max_retries} attempts.")


def fetch_snapshot(limit: int = DEFAULT_LIMIT, is_sync: bool = False) -> dict:
    """Fetch paginated CVE records from NVD up to the specified limit, or sync incrementally."""
    api_key = os.environ.get("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        log.info("Using NVD API key from environment.")
    else:
        log.warning("No NVD API key found. API rate limits will be restrictive.")

    params = {
        "resultsPerPage": min(RESULTS_PER_PAGE, limit)
    }

    if is_sync:
        last_mod = get_last_modified_timestamp()
        if last_mod:
            # Shift back by 1 hour to ensure we don't miss overlapping updates due to clock drift
            try:
                dt = datetime.datetime.fromisoformat(last_mod.split(".")[0])
                sync_start = (dt - datetime.timedelta(hours=1)).isoformat()
            except ValueError:
                sync_start = last_mod
            
            # End date is now (UTC)
            sync_end = datetime.datetime.utcnow().isoformat()
            
            params["lastModStartDate"] = sync_start
            params["lastModEndDate"] = sync_end
            log.info("Incremental Sync Mode: fetching updates modified between %s and %s", sync_start, sync_end)
        else:
            log.info("No previous records found. Performing full initial ingest.")

    start_index = 0
    all_vulnerabilities = []
    total_results = None

    while True:
        params["startIndex"] = start_index
        data = fetch_page_with_retry(params, headers)
        
        if total_results is None:
            total_results = data.get("totalResults", 0)
            log.info("NVD reports %d total matching vulnerabilities.", total_results)
            
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        all_vulnerabilities.extend(vulnerabilities)
        log.info("Retrieved %d/%d records...", len(all_vulnerabilities), min(total_results, limit if not is_sync else total_results))
        
        if len(all_vulnerabilities) >= limit and not is_sync:
            log.info("Reached requested limit of %d records.", limit)
            all_vulnerabilities = all_vulnerabilities[:limit]
            break
            
        start_index += len(vulnerabilities)
        if start_index >= total_results:
            break

    # Format return JSON to match original schema shape
    return {
        "totalResults": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities
    }


def main():
    parser = argparse.ArgumentParser(description="Fetch NVD CVE snapshot resiliently.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max CVEs to fetch (default: 5000)")
    parser.add_argument("--sync", action="store_true", help="Perform incremental delta sync since last run")
    args = parser.parse_args()

    log.info("Starting NVD snapshot download...")
    data = fetch_snapshot(limit=args.limit, is_sync=args.sync)
    
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    if args.sync and OUTPUT_PATH.exists():
        # Merge delta updates into existing raw snapshot
        try:
            existing = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
            existing_vuls = {v["cve"]["id"]: v for v in existing.get("vulnerabilities", [])}
            
            # Upsert new updates
            new_count = 0
            for v in data.get("vulnerabilities", []):
                cid = v["cve"]["id"]
                if cid not in existing_vuls:
                    new_count += 1
                existing_vuls[cid] = v
                
            data = {
                "totalResults": len(existing_vuls),
                "vulnerabilities": list(existing_vuls.values())
            }
            log.info("Merged %d new/updated vulnerabilities into existing raw dataset.", new_count)
        except Exception as e:
            log.error("Failed to merge sync updates: %s. Overwriting raw snapshot instead.", e)

    OUTPUT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("Saved raw snapshot: %d vulnerabilities total -> %s", len(data.get("vulnerabilities", [])), OUTPUT_PATH)


if __name__ == "__main__":
    main()
