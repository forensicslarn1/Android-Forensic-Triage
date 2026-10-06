#!/usr/bin/env python3
"""
========================================================================================
 4nsicsLarn - Android Forensic Triage Tool
 Comprehensive Digital Forensics Triage & Chronological Timeline Analysis for Android
========================================================================================
Author: 4nsicsLarn Development Team
License: MIT
Description:
  Automated digital forensics tool designed to inspect Android SQLite databases
  (Call Logs, SMS/MMS, Chrome History), verify cryptographic integrity via SHA-256/MD5,
  aggregate events into a unified chronological timeline, and produce an interactive
  forensic triage HTML report with charts, search filters, and chain-of-custody logging.
"""

import os
import sys
import argparse
import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure UTF-8 console output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Import 4nsicsLarn modules
try:
    from hasher import compute_file_hashes
    from parsers import parse_call_logs, parse_sms_messages, parse_chrome_history
    from timeline import build_unified_timeline, aggregate_timeline_stats
    from html_reporter import generate_html_report
    from mock_data_generator import create_mock_evidence_directory
except ImportError:
    # If run from another directory, add script directory to sys.path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, script_dir)
    from hasher import compute_file_hashes
    from parsers import parse_call_logs, parse_sms_messages, parse_chrome_history
    from timeline import build_unified_timeline, aggregate_timeline_stats
    from html_reporter import generate_html_report
    from mock_data_generator import create_mock_evidence_directory

BANNER = r"""
  ██╗  ██╗███╗   ██╗███████╗██╗ ██████╗███████╗██╗      █████╗ ██████╗ ███╗   ██╗
  ██║  ██║████╗  ██║██╔════╝██║██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗████╗  ██║
  ███████║██╔██╗ ██║███████╗██║██║     ███████╗██║     ███████║██████╔╝██╔██╗ ██║
  ╚════██║██║╚██╗██║╚════██║██║██║     ╚════██║██║     ██╔══██║██╔══██╗██║╚██╗██║
       ██║██║ ╚████║███████║██║╚██████╗███████║███████╗██║  ██║██║  ██║██║ ╚████║
       ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
               [ Android Mobile Digital Forensics Triage Tool v1.0.0 ]
"""

def detect_database_type(db_path: str) -> str:
    """
    Inspects an SQLite file to determine whether it contains calls, sms, or web history.
    """
    if not os.path.isfile(db_path):
        return "unknown"

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        if "calls" in tables:
            return "calls"
        elif "sms" in tables:
            return "sms"
        elif "urls" in tables and "visits" in tables:
            return "chrome"
    except Exception:
        pass

    # Fallback to file name heuristics
    base_lower = os.path.basename(db_path).lower()
    if "call" in base_lower or "contacts2" in base_lower:
        return "calls"
    elif "sms" in base_lower or "mms" in base_lower:
        return "sms"
    elif "history" in base_lower or "chrome" in base_lower:
        return "chrome"

    return "unknown"

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="4nsicsLarn: Digital Forensics Triage & Chronological Timeline Analysis for Android",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--input", help="Directory containing extracted Android SQLite databases (or single DB file)")
    parser.add_argument("-o", "--output", default="forensic_output", help="Directory to save generated forensic reports and manifests (default: forensic_output)")
    parser.add_argument("--case-id", default="CAS-2026-0491", help="Forensic Case Identifier (e.g. CAS-2026-001)")
    parser.add_argument("--evidence-id", default="EVD-AND-01", help="Evidence Item Identification Tag (e.g. EVD-01)")
    parser.add_argument("--examiner", default="Digital Forensics Investigator", help="Name or Badge ID of the forensic examiner")
    parser.add_argument("--agency", default="Cyber Crime & Forensics Unit", help="Investigative Department / Agency / Lab")
    parser.add_argument("--notes", default="Forensic triage of Android device storage. Databases analyzed with cryptographic hash verification.", help="Case notes or examiner observations")
    parser.add_argument("--demo", action="store_true", help="Generate realistic mock Android databases and execute complete forensic workflow")

    args = parser.parse_args()

    # Handle demo mode
    if args.demo:
        print("[*] Running in DEMO mode: Generating realistic Android mock evidence databases...")
        demo_dir = os.path.join(args.output, "mock_evidence_source")
        create_mock_evidence_directory(demo_dir)
        args.input = demo_dir

    if not args.input:
        parser.print_help()
        print("\n[-] Error: Please specify an input directory with -i / --input or use --demo to test.")
        sys.exit(1)

    if not os.path.exists(args.input):
        print(f"[-] Error: Input path does not exist: {args.input}")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # 1. Discover Evidence Files
    evidence_files = []
    if os.path.isfile(args.input):
        evidence_files.append(os.path.abspath(args.input))
    else:
        for root, _, files in os.walk(args.input):
            for file in files:
                # Exclude temporary, journal, or lock files
                if file.endswith("-journal") or file.endswith("-wal") or file.endswith("-shm"):
                    continue
                full_path = os.path.abspath(os.path.join(root, file))
                evidence_files.append(full_path)

    if not evidence_files:
        print(f"[-] No evidence files found in {args.input}")
        sys.exit(1)

    print(f"[+] Found {len(evidence_files)} potential file(s) for examination.")

    # 2. Forensic Hashing (Chain of Custody & Integrity)
    print("\n[*] Step 1: Computing cryptographic hashes (SHA-256 & MD5) for forensic integrity...")
    evidence_hashes = []
    hash_manifest_lines = [
        f"# 4nsicsLarn Cryptographic Hash Manifest",
        f"# Generated: {datetime.now(timezone.utc).isoformat()} UTC",
        f"# Case ID: {args.case_id} | Evidence ID: {args.evidence_id}",
        f"# Examiner: {args.examiner}",
        "# " + "=" * 70,
        ""
    ]

    for file_path in evidence_files:
        try:
            hash_info = compute_file_hashes(file_path)
            evidence_hashes.append(hash_info)
            print(f"    [OK] {hash_info['file_name']} ({hash_info['file_size_formatted']})")
            print(f"         SHA-256: {hash_info['sha256']}")
            hash_manifest_lines.append(f"{hash_info['sha256']}  {os.path.basename(file_path)}")
        except Exception as e:
            print(f"    [!] Error hashing {file_path}: {e}")

    # Write SHA-256 manifest to output
    manifest_path = os.path.join(args.output, f"hashes_{args.case_id}.sha256")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(hash_manifest_lines) + "\n")
    print(f"[+] Cryptographic manifest saved to: {manifest_path}")

    # 3. Parse SQLite Databases
    print("\n[*] Step 2: Parsing Android SQLite databases...")
    all_calls = []
    all_sms = []
    all_history = []

    for file_path in evidence_files:
        db_type = detect_database_type(file_path)
        base_name = os.path.basename(file_path)

        if db_type == "calls":
            print(f"    [+] Parsing Call Logs database: {base_name}")
            try:
                calls = parse_call_logs(file_path)
                all_calls.extend(calls)
                print(f"        -> Extracted {len(calls)} call record(s)")
            except Exception as e:
                print(f"        [!] Error parsing calls from {base_name}: {e}")

        elif db_type == "sms":
            print(f"    [+] Parsing SMS/MMS database: {base_name}")
            try:
                sms_list = parse_sms_messages(file_path)
                all_sms.extend(sms_list)
                print(f"        -> Extracted {len(sms_list)} SMS message(s)")
            except Exception as e:
                print(f"        [!] Error parsing SMS from {base_name}: {e}")

        elif db_type == "chrome":
            print(f"    [+] Parsing Browser History database: {base_name}")
            try:
                history_list = parse_chrome_history(file_path)
                all_history.extend(history_list)
                print(f"        -> Extracted {len(history_list)} browsing URL record(s)")
            except Exception as e:
                print(f"        [!] Error parsing Chrome history from {base_name}: {e}")

    # 4. Build Unified Chronological Timeline
    print("\n[*] Step 3: Aggregating into Unified Chronological Timeline...")
    timeline_events = build_unified_timeline(all_calls, all_sms, all_history)
    timeline_stats = aggregate_timeline_stats(timeline_events)
    print(f"[+] Total timeline events: {len(timeline_events)}")
    if timeline_events:
        print(f"    Earliest Event: {timeline_stats['earliest_date']}")
        print(f"    Latest Event:   {timeline_stats['latest_date']}")

    # 5. Generate Interactive Forensic HTML Report
    print("\n[*] Step 4: Compiling interactive forensic HTML report...")
    report_filename = f"forensic_report_{args.case_id}.html"
    report_path = os.path.join(args.output, report_filename)

    case_metadata = {
        "case_id": args.case_id,
        "evidence_id": args.evidence_id,
        "examiner": args.examiner,
        "agency": args.agency,
        "notes": args.notes,
        "generation_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    generate_html_report(
        case_meta=case_metadata,
        evidence_hashes=evidence_hashes,
        calls=all_calls,
        sms_messages=all_sms,
        history=all_history,
        timeline_events=timeline_events,
        timeline_stats=timeline_stats,
        output_html_path=report_path
    )
    print(f"[OK] Interactive Forensic Report successfully generated:")
    print(f"     => {os.path.abspath(report_path)}")

    # 6. Generate Machine-Readable JSON Export
    json_path = os.path.join(args.output, f"triage_summary_{args.case_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "case_metadata": case_metadata,
            "evidence_integrity": evidence_hashes,
            "stats": {
                "total_calls": len(all_calls),
                "total_sms": len(all_sms),
                "total_history": len(all_history),
                "total_timeline_events": len(timeline_events)
            },
            "timeline_events": timeline_events[:500]  # top 500 events summary
        }, f, indent=2, ensure_ascii=False)
    print(f"[OK] JSON Triage summary exported: {json_path}")

    print("\n" + "=" * 75)
    print("               [ FORENSIC ANALYSIS COMPLETED SUCCESSFULLY ]")
    print("=" * 75)
    print(f"  • Case Number:       {args.case_id}")
    print(f"  • Examiner:          {args.examiner}")
    print(f"  • Evidence Files:    {len(evidence_hashes)}")
    print(f"  • Total Calls:       {len(all_calls)}")
    print(f"  • Total SMS:         {len(all_sms)}")
    print(f"  • Web History URLs:  {len(all_history)}")
    print(f"  • Unified Timeline:  {len(timeline_events)} events")
    print(f"  • HTML Report:       {os.path.abspath(report_path)}")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    main()
