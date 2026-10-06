"""
4nsicsLarn - Unified Forensic Timeline Builder
Aggregates artifacts from Calls, SMS, and Browsing history into a single chronological timeline.
Provides statistical aggregation for timeline analytics and charts.
"""

from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime, timezone

def build_unified_timeline(
    calls: List[Dict[str, Any]],
    sms_messages: List[Dict[str, Any]],
    history: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Combines all forensic artifacts into a unified chronological event list.
    """
    events = []

    # Process Calls
    for call in calls:
        if call.get("timestamp_epoch", 0) <= 0:
            continue
        events.append({
            "timestamp_utc": call["timestamp_utc"],
            "timestamp_epoch": call["timestamp_epoch"],
            "artifact_type": "CALL",
            "action": f"Call: {call['call_type']}",
            "entity": f"{call['contact_name']} ({call['phone_number']})",
            "summary": f"Duration: {call['duration_formatted']} | Loc: {call['location']}",
            "source_file": call["source_file"],
            "record_id": call["record_id"],
            "details": call
        })

    # Process SMS
    for sms in sms_messages:
        if sms.get("timestamp_epoch", 0) <= 0:
            continue
        events.append({
            "timestamp_utc": sms["timestamp_utc"],
            "timestamp_epoch": sms["timestamp_epoch"],
            "artifact_type": "SMS",
            "action": f"SMS: {sms['message_type']}",
            "entity": sms["address"],
            "summary": sms["body"],
            "source_file": sms["source_file"],
            "record_id": sms["record_id"],
            "details": sms
        })

    # Process Browsing
    for item in history:
        if item.get("timestamp_epoch", 0) <= 0:
            continue
        events.append({
            "timestamp_utc": item["timestamp_utc"],
            "timestamp_epoch": item["timestamp_epoch"],
            "artifact_type": "BROWSER",
            "action": f"Web Visit ({item['visit_count']}x)",
            "entity": item["domain"],
            "summary": f"{item['title']} - {item['url']}",
            "source_file": item["source_file"],
            "record_id": item["record_id"],
            "details": item
        })

    # Sort chronologically by timestamp_epoch (oldest to newest)
    events.sort(key=lambda x: x["timestamp_epoch"])

    return events

def aggregate_timeline_stats(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes statistical aggregations on the unified timeline for visualization.
    """
    if not events:
        return {
            "total_events": 0,
            "earliest_date": "N/A",
            "latest_date": "N/A",
            "dates": [],
            "calls_by_date": [],
            "sms_by_date": [],
            "browser_by_date": []
        }

    daily_counts = defaultdict(lambda: {"CALL": 0, "SMS": 0, "BROWSER": 0})

    for event in events:
        epoch = event["timestamp_epoch"]
        if epoch <= 0:
            continue
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        date_str = dt.strftime("%Y-%m-%d")
        daily_counts[date_str][event["artifact_type"]] += 1

    sorted_dates = sorted(daily_counts.keys())

    calls_by_date = [daily_counts[d]["CALL"] for d in sorted_dates]
    sms_by_date = [daily_counts[d]["SMS"] for d in sorted_dates]
    browser_by_date = [daily_counts[d]["BROWSER"] for d in sorted_dates]

    earliest_date = events[0]["timestamp_utc"]
    latest_date = events[-1]["timestamp_utc"]

    return {
        "total_events": len(events),
        "earliest_date": earliest_date,
        "latest_date": latest_date,
        "dates": sorted_dates,
        "calls_by_date": calls_by_date,
        "sms_by_date": sms_by_date,
        "browser_by_date": browser_by_date
    }
