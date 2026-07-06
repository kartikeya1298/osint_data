"""
merge_osint_csv.py
──────────────────
Merges all military_osint_data_*.csv files in the current directory into a
single deduplicated output file.

Deduplication logic (in priority order):
  1. Exact threat_id match                  → duplicate
  2. Same ioc_value + category_code         → duplicate
  3. Same post_url (non-empty)              → duplicate

Usage:
    python merge_osint_csv.py                          # auto-discovers CSVs in CWD
    python merge_osint_csv.py *.csv                    # explicit file list
    python merge_osint_csv.py --dir C:/path/to/csvs   # specific folder
    python merge_osint_csv.py --out merged.csv         # custom output name

Output:
    merged_osint_<timestamp>.csv  (same columns as source files)
"""

import csv
import glob
import sys
import os
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

# ── Column order — matches military_osint_tool.py CSV_COLUMNS exactly ─────────
CSV_COLUMNS = [
    "threat_id",
    "threat_name",
    "category_code",
    "category_name",
    "source_layer",
    "source",
    "post_text",
    "post_url",
    "timestamp",
    "location",
    "severity",
    "confidence",
    "ioc_type",
    "ioc_value",
    "tags",
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("merge_osint")


# ── Helpers ───────────────────────────────────────────────────────────────────
def normalise(val: str) -> str:
    """Strip whitespace and lowercase for comparison."""
    return (val or "").strip().lower()


def is_duplicate(row: dict, seen_ids: set, seen_ioc: set, seen_urls: set) -> bool:
    tid  = normalise(row.get("threat_id", ""))
    ioc  = normalise(row.get("ioc_value", ""))
    cat  = normalise(row.get("category_code", ""))
    url  = normalise(row.get("post_url", ""))

    if tid and tid in seen_ids:
        return True
    ioc_key = f"{cat}|{ioc}"
    if ioc and ioc_key in seen_ioc:
        return True
    if url and url in seen_urls:
        return True
    return False


def mark_seen(row: dict, seen_ids: set, seen_ioc: set, seen_urls: set):
    tid  = normalise(row.get("threat_id", ""))
    ioc  = normalise(row.get("ioc_value", ""))
    cat  = normalise(row.get("category_code", ""))
    url  = normalise(row.get("post_url", ""))

    if tid:  seen_ids.add(tid)
    if ioc:  seen_ioc.add(f"{cat}|{ioc}")
    if url:  seen_urls.add(url)


def read_csv(path: Path) -> list[dict]:
    """Read a CSV, strip BOM from headers, fill missing columns with empty string."""
    rows = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            # Clean up any stray whitespace in header names
            if reader.fieldnames:
                reader.fieldnames = [h.strip() for h in reader.fieldnames]
            for row in reader:
                rows.append(row)
        log.info(f"  Read {len(rows):>5} rows  ← {path.name}")
    except Exception as e:
        log.warning(f"  Skipped {path.name}: {e}")
    return rows


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Merge & deduplicate military OSINT CSV files.")
    parser.add_argument("files", nargs="*",  help="Explicit CSV file paths (optional)")
    parser.add_argument("--dir", default=".", help="Folder to scan for military_osint_data_*.csv (default: CWD)")
    parser.add_argument("--out", default="",  help="Output filename (default: merged_osint_<timestamp>.csv)")
    parser.add_argument("--pattern", default="military_osint_data_*.csv",
                        help="Glob pattern for auto-discovery (default: military_osint_data_*.csv)")
    args = parser.parse_args()

    # ── Collect input files ───────────────────────────────────────────────────
    if args.files:
        input_files = [Path(f) for f in args.files]
    else:
        scan_dir = Path(args.dir)
        input_files = sorted(scan_dir.glob(args.pattern))

    if not input_files:
        log.error(f"No CSV files found. Use --dir or pass file paths explicitly.")
        sys.exit(1)

    log.info(f"Found {len(input_files)} input file(s):")

    # ── Determine output columns ──────────────────────────────────────────────
    # Use the canonical column list; if a file has extra columns, append them.
    all_columns = list(CSV_COLUMNS)
    all_rows_raw: list[dict] = []

    for path in input_files:
        file_rows = read_csv(path)
        for row in file_rows:
            for col in row:
                if col not in all_columns:
                    all_columns.append(col)
        all_rows_raw.extend(file_rows)

    log.info(f"Total rows before dedup : {len(all_rows_raw)}")

    # ── Deduplicate ───────────────────────────────────────────────────────────
    seen_ids  : set = set()
    seen_ioc  : set = set()
    seen_urls : set = set()

    unique_rows  : list[dict] = []
    dup_count = 0

    for row in all_rows_raw:
        if is_duplicate(row, seen_ids, seen_ioc, seen_urls):
            dup_count += 1
            continue
        mark_seen(row, seen_ids, seen_ioc, seen_urls)
        # Normalise row to canonical columns, fill blanks
        clean = {col: row.get(col, "") for col in all_columns}
        unique_rows.append(clean)

    log.info(f"Duplicates removed       : {dup_count}")
    log.info(f"Unique rows kept         : {len(unique_rows)}")

    # ── Write output ──────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_name = args.out or f"merged_osint_{ts}.csv"
    out_path = Path(args.dir) / out_name if not args.out else Path(out_name)

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=all_columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(unique_rows)

    log.info(f"Output written           : {out_path.resolve()}")
    log.info("=" * 60)
    log.info(f"  Input files   : {len(input_files)}")
    log.info(f"  Input rows    : {len(all_rows_raw)}")
    log.info(f"  Duplicates    : {dup_count}")
    log.info(f"  Unique output : {len(unique_rows)}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
