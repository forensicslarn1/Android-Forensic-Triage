"""
4nsicsLarn - Android SQLite Parsers
Robust parsers for Call Logs, SMS/MMS messages, and Chrome/Browser History.
Extracts artifacts, normalizes timestamps, and handles diverse Android database variations.
"""

import sqlite3
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

CALL_TYPES = {
    1: "Incoming",
    2: "Outgoing",
    3: "Missed",
    4: "Voicemail",
    5: "Rejected",
    6: "Blocked",
    7: "Answered Externally"
}

SMS_TYPES = {
    1: "Received (Inbox)",
    2: "Sent",
    3: "Draft",
    4: "Outbox",
    5: "Failed",
    6: "Queued"
}

def convert_epoch_ms_to_datetime(epoch_ms: int) -> Tuple[datetime, str, float]:
    """
    Converts Android epoch milliseconds to (datetime_obj, iso_utc_str, epoch_seconds).
    Handles millisecond vs second timestamps automatically.
    """
    try:
        if epoch_ms > 1e11:  # Milliseconds
            epoch_sec = epoch_ms / 1000.0
        else:  # Already seconds
            epoch_sec = float(epoch_ms)
        
        dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        iso_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return dt, iso_str, epoch_sec
    except Exception:
        dt = datetime.fromtimestamp(0, tz=timezone.utc)
        return dt, "1970-01-01 00:00:00 UTC", 0.0

def convert_chrome_time_to_datetime(chrome_time: int) -> Tuple[datetime, str, float]:
    """
    Converts WebKit / Chrome microsecond timestamp (since 1601-01-01 UTC)
    to (datetime_obj, iso_utc_str, epoch_seconds).
    """
    try:
        if chrome_time <= 0:
            dt = datetime.fromtimestamp(0, tz=timezone.utc)
            return dt, "N/A", 0.0
        
        # Chrome stores microseconds since Jan 1, 1601
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        if chrome_time > 1e15:
            epoch_sec = (chrome_time / 1_000_000.0) - 11644473600.0
        elif chrome_time > 1e11: # Milliseconds fallback
            epoch_sec = chrome_time / 1000.0
        else:
            epoch_sec = float(chrome_time)

        if epoch_sec < 0:
            epoch_sec = 0.0

        dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        iso_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return dt, iso_str, epoch_sec
    except Exception:
        dt = datetime.fromtimestamp(0, tz=timezone.utc)
        return dt, "N/A", 0.0

def format_duration(seconds: int) -> str:
    """Formats duration in seconds to HH:MM:SS or MM:SS."""
    try:
        seconds = int(seconds)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"
    except Exception:
        return "00:00"

def get_table_columns(cursor: sqlite3.Cursor, table_name: str) -> List[str]:
    """Inspects table columns using PRAGMA table_info."""
    try:
        cursor.execute(f"PRAGMA table_info({table_name});")
        return [row[1] for row in cursor.fetchall()]
    except Exception:
        return []

def parse_call_logs(db_path: str) -> List[Dict[str, Any]]:
    """
    Parses Android Call Logs from calls table in contacts2.db or calllog.db.
    """
    results = []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()

    try:
        # Check if calls table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls';")
        if not cursor.fetchone():
            return results

        columns = get_table_columns(cursor, "calls")
        has_name = "name" in columns
        has_location = "geocoded_location" in columns
        has_duration = "duration" in columns
        has_type = "type" in columns
        has_number = "number" in columns
        has_date = "date" in columns

        query = f"""
        SELECT 
            _id,
            { 'number' if has_number else "'' as number" },
            { 'date' if has_date else "0 as date" },
            { 'duration' if has_duration else "0 as duration" },
            { 'type' if has_type else "1 as type" },
            { 'name' if has_name else "'' as name" },
            { 'geocoded_location' if has_location else "'' as geocoded_location" }
        FROM calls
        ORDER BY date DESC;
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            record_id, number, date_val, duration, ctype, name, loc = row
            _, iso_time, epoch_sec = convert_epoch_ms_to_datetime(date_val or 0)
            
            call_type_str = CALL_TYPES.get(ctype, f"Unknown ({ctype})")
            
            results.append({
                "record_id": record_id,
                "phone_number": number or "Unknown",
                "contact_name": name or "Unknown / Unsaved",
                "call_type": call_type_str,
                "raw_type": ctype,
                "duration_seconds": duration or 0,
                "duration_formatted": format_duration(duration or 0),
                "timestamp_utc": iso_time,
                "timestamp_epoch": epoch_sec,
                "location": loc or "N/A",
                "source_file": db_path
            })
    finally:
        conn.close()

    return results

def parse_sms_messages(db_path: str) -> List[Dict[str, Any]]:
    """
    Parses Android SMS messages from mmssms.db (table sms).
    """
    results = []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms';")
        if not cursor.fetchone():
            return results

        columns = get_table_columns(cursor, "sms")
        has_address = "address" in columns
        has_body = "body" in columns
        has_date = "date" in columns
        has_type = "type" in columns
        has_read = "read" in columns
        has_thread = "thread_id" in columns
        has_creator = "creator" in columns

        query = f"""
        SELECT 
            _id,
            { 'address' if has_address else "'' as address" },
            { 'date' if has_date else "0 as date" },
            { 'type' if has_type else "1 as type" },
            { 'body' if has_body else "'' as body" },
            { 'read' if has_read else "1 as read" },
            { 'thread_id' if has_thread else "0 as thread_id" },
            { 'creator' if has_creator else "'' as creator" }
        FROM sms
        ORDER BY date DESC;
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            record_id, address, date_val, msg_type, body, read_val, thread_id, creator = row
            _, iso_time, epoch_sec = convert_epoch_ms_to_datetime(date_val or 0)
            
            sms_type_str = SMS_TYPES.get(msg_type, f"Unknown ({msg_type})")

            results.append({
                "record_id": record_id,
                "address": address or "Unknown",
                "message_type": sms_type_str,
                "raw_type": msg_type,
                "body": body or "",
                "read": bool(read_val),
                "thread_id": thread_id,
                "creator_app": creator or "Default SMS App",
                "timestamp_utc": iso_time,
                "timestamp_epoch": epoch_sec,
                "source_file": db_path
            })
    finally:
        conn.close()

    return results

def parse_chrome_history(db_path: str) -> List[Dict[str, Any]]:
    """
    Parses Android Chrome / Chromium History database (tables urls and visits).
    """
    results = []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls';")
        if not cursor.fetchone():
            return results

        columns = get_table_columns(cursor, "urls")
        has_url = "url" in columns
        has_title = "title" in columns
        has_vcount = "visit_count" in columns
        has_tcount = "typed_count" in columns
        has_time = "last_visit_time" in columns

        query = f"""
        SELECT 
            id,
            { 'url' if has_url else "'' as url" },
            { 'title' if has_title else "'' as title" },
            { 'visit_count' if has_vcount else "1 as visit_count" },
            { 'typed_count' if has_tcount else "0 as typed_count" },
            { 'last_visit_time' if has_time else "0 as last_visit_time" }
        FROM urls
        ORDER BY last_visit_time DESC;
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            record_id, url_str, title_str, visit_count, typed_count, last_visit_time = row
            _, iso_time, epoch_sec = convert_chrome_time_to_datetime(last_visit_time or 0)
            
            # Extract domain name
            try:
                parsed_url = urllib.parse.urlparse(url_str)
                domain = parsed_url.netloc or "Unknown Domain"
            except Exception:
                domain = "Unknown Domain"

            results.append({
                "record_id": record_id,
                "url": url_str or "",
                "title": title_str or "No Title",
                "domain": domain,
                "visit_count": visit_count or 1,
                "typed_count": typed_count or 0,
                "last_visit_time_raw": last_visit_time,
                "timestamp_utc": iso_time,
                "timestamp_epoch": epoch_sec,
                "source_file": db_path
            })
    finally:
        conn.close()

    return results

def detect_database_type(db_path: str) -> str:
    """
    Inspects an SQLite file to determine whether it contains calls, sms, or web history.
    """
    import os
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

    # Heuristic fallback based on filename
    base_lower = os.path.basename(db_path).lower()
    if "call" in base_lower or "contacts2" in base_lower:
        return "calls"
    elif "sms" in base_lower or "mms" in base_lower:
        return "sms"
    elif "history" in base_lower or "chrome" in base_lower:
        return "chrome"

    return "unknown"

