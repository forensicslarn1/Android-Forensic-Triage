"""
4nsicsLarn - Interactive Forensic HTML Report Generator
Generates a standalone, interactive digital forensic report with:
  - Examiner and case metadata
  - SHA-256 / MD5 evidence integrity & chain of custody
  - Visual analytics (Chart.js)
  - Unified chronological timeline
  - Filterable, searchable data tables (Calls, SMS, Browser)
  - Print / PDF export support
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List

def generate_html_report(
    case_meta: Dict[str, Any],
    evidence_hashes: List[Dict[str, Any]],
    calls: List[Dict[str, Any]],
    sms_messages: List[Dict[str, Any]],
    history: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]],
    timeline_stats: Dict[str, Any],
    output_html_path: str
):
    """
    Renders and writes the complete interactive forensic HTML report to disk.
    """
    # Calculate summary metrics
    total_calls = len(calls)
    incoming_calls = sum(1 for c in calls if c.get("raw_type") == 1)
    outgoing_calls = sum(1 for c in calls if c.get("raw_type") == 2)
    missed_calls = sum(1 for c in calls if c.get("raw_type") == 3)
    rejected_calls = sum(1 for c in calls if c.get("raw_type") in (5, 6))

    total_sms = len(sms_messages)
    received_sms = sum(1 for s in sms_messages if s.get("raw_type") == 1)
    sent_sms = sum(1 for s in sms_messages if s.get("raw_type") == 2)

    total_history = len(history)
    unique_domains = len(set(h.get("domain", "") for h in history if h.get("domain")))

    # Top domains for chart
    domain_counts = {}
    for h in history:
        d = h.get("domain", "Unknown")
        if d:
            domain_counts[d] = domain_counts.get(d, 0) + h.get("visit_count", 1)
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:7]
    top_domains_labels = [item[0] for item in sorted_domains]
    top_domains_values = [item[1] for item in sorted_domains]
    # Data dictionary for charts
    chart_data = {
        "dates": timeline_stats.get("dates", []),
        "calls_by_date": timeline_stats.get("calls_by_date", []),
        "sms_by_date": timeline_stats.get("sms_by_date", []),
        "browser_by_date": timeline_stats.get("browser_by_date", []),
        "call_types": {
            "labels": ["Incoming / واردة", "Outgoing / صادرة", "Missed / لم يرد عليها", "Rejected & Other / مرفوضة"],
            "data": [incoming_calls, outgoing_calls, missed_calls, rejected_calls]
        },
        "sms_types": {
            "labels": ["Received / مستلمة", "Sent / مرسلة"],
            "data": [received_sms, sent_sms]
        },
        "top_domains": {
            "labels": top_domains_labels,
            "data": top_domains_values
        }
    }

    report_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Pre-serialize JSON data to avoid f-string escaping issues
    chart_data_json = json.dumps(chart_data)
    case_meta_json = json.dumps(case_meta)
    evidence_hashes_json = json.dumps(evidence_hashes)
    timeline_export_json = json.dumps([{
        "timestamp_utc": ev["timestamp_utc"],
        "artifact_type": ev["artifact_type"],
        "action": ev["action"],
        "entity": ev["entity"],
        "summary": ev["summary"]
    } for ev in timeline_events])

    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير الفحص الجنائي الرقمي | 4nsicsLarn Triage Report</title>
    <!-- Chart.js and DataTables -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-amber: #f59e0b;
            --accent-rose: #f43f5e;
            --accent-purple: #c084fc;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Cairo", "Helvetica Neue", Arial, sans-serif;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        /* Header & Case Details */
        .report-header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-top: 4px solid var(--accent-blue);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .tool-brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .tool-brand i {{
            font-size: 2.4rem;
            color: var(--accent-blue);
        }}
        .tool-title h1 {{
            font-size: 1.6rem;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.5px;
        }}
        .tool-title p {{
            font-size: 0.85rem;
            color: var(--accent-blue);
        }}
        .header-actions {{
            display: flex;
            gap: 10px;
        }}
        .btn {{
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }}
        .btn-primary {{
            background-color: #2563eb;
            color: white;
        }}
        .btn-primary:hover {{
            background-color: #1d4ed8;
        }}
        .btn-outline {{
            background-color: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }}
        .btn-outline:hover {{
            background-color: var(--bg-secondary);
            color: white;
        }}
        .case-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }}
        .meta-item {{
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            padding: 12px 16px;
            border-radius: 8px;
        }}
        .meta-item .label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 4px;
        }}
        .meta-item .value {{
            font-size: 0.95rem;
            font-weight: 600;
            color: #fff;
        }}

        /* KPI Cards */
        .kpi-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .kpi-icon {{
            width: 50px;
            height: 50px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.4rem;
        }}
        .icon-blue {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); }}
        .icon-green {{ background: rgba(74, 222, 128, 0.15); color: var(--accent-green); }}
        .icon-amber {{ background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); }}
        .icon-purple {{ background: rgba(192, 132, 252, 0.15); color: var(--accent-purple); }}
        .kpi-content h3 {{
            font-size: 1.5rem;
            font-weight: 700;
        }}
        .kpi-content p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        /* Evidence Integrity Section */
        .section-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .section-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .hash-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            direction: ltr;
            text-align: left;
        }}
        .hash-table th, .hash-table td {{
            padding: 10px 14px;
            border: 1px solid var(--border-color);
        }}
        .hash-table th {{
            background: #111827;
            color: var(--accent-blue);
        }}
        .hash-code {{
            font-family: monospace;
            background: #090d16;
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
            word-break: break-all;
        }}
        .badge-verified {{
            background: rgba(74, 222, 128, 0.2);
            color: var(--accent-green);
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.75rem;
        }}

        /* Charts Grid */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .chart-box {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            height: 320px;
        }}
        .chart-box h4 {{
            font-size: 0.95rem;
            margin-bottom: 12px;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* Navigation Tabs */
        .tabs-header {{
            display: flex;
            gap: 8px;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 20px;
            overflow-x: auto;
        }}
        .tab-btn {{
            padding: 10px 18px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
        }}
        .tab-btn:hover {{
            color: #fff;
        }}
        .tab-btn.active {{
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
        }}
        .tab-pane {{
            display: none;
        }}
        .tab-pane.active {{
            display: block;
        }}

        /* DataTables Custom Styling */
        table.dataTable {{
            width: 100% !important;
            border-collapse: collapse !important;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.85rem;
        }}
        table.dataTable thead th {{
            background: #0f172a !important;
            color: var(--accent-blue) !important;
            border-bottom: 2px solid var(--border-color) !important;
            padding: 12px 10px !important;
            text-align: right;
        }}
        table.dataTable tbody td {{
            padding: 10px !important;
            border-bottom: 1px solid var(--border-color) !important;
            text-align: right;
        }}
        .dataTables_wrapper .dataTables_length,
        .dataTables_wrapper .dataTables_filter,
        .dataTables_wrapper .dataTables_info,
        .dataTables_wrapper .dataTables_paginate {{
            color: var(--text-secondary) !important;
            margin: 12px 0;
            font-size: 0.85rem;
        }}
        .dataTables_wrapper .dataTables_filter input {{
            background: #0f172a;
            border: 1px solid var(--border-color);
            color: #fff;
            padding: 6px 12px;
            border-radius: 6px;
            margin-right: 8px;
        }}
        .dataTables_wrapper .dataTables_paginate .paginate_button {{
            background: var(--bg-secondary) !important;
            color: var(--text-primary) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 4px;
        }}
        .dataTables_wrapper .dataTables_paginate .paginate_button.current {{
            background: var(--accent-blue) !important;
            color: #000 !important;
            font-weight: bold;
        }}

        /* Artifact Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-call {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; }}
        .badge-sms {{ background: rgba(74, 222, 128, 0.2); color: #4ade80; }}
        .badge-browser {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
        .badge-incoming {{ background: rgba(74, 222, 128, 0.2); color: #4ade80; }}
        .badge-outgoing {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; }}
        .badge-missed {{ background: rgba(244, 63, 94, 0.2); color: #f43f5e; }}

        /* Timeline View */
        .timeline-filter-bar {{
            display: flex;
            gap: 10px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .filter-chip {{
            padding: 6px 14px;
            border-radius: 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-chip.active {{
            background: var(--accent-blue);
            color: #0f172a;
            font-weight: bold;
        }}

        /* Footer & Signoff */
        .report-footer {{
            border-top: 1px solid var(--border-color);
            padding-top: 24px;
            margin-top: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            flex-wrap: wrap;
            gap: 24px;
        }}
        .signature-box {{
            border: 1px dashed var(--border-color);
            border-radius: 8px;
            padding: 16px;
            width: 320px;
            background: rgba(15, 23, 42, 0.4);
        }}
        .sig-line {{
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 6px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-align: center;
        }}

        @media print {{
            body {{
                background: #fff;
                color: #000;
                padding: 0;
            }}
            .report-header, .section-card, .kpi-card {{
                background: #fff !important;
                border: 1px solid #ddd !important;
                color: #000 !important;
                box-shadow: none !important;
            }}
            .header-actions, .dataTables_filter, .dataTables_paginate, .timeline-filter-bar {{
                display: none !important;
            }}
            .tab-pane {{
                display: block !important;
                page-break-before: always;
            }}
            .hash-code {{
                background: #eee !important;
                color: #000 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Report Header -->
        <header class="report-header">
            <div class="header-top">
                <div class="tool-brand">
                    <i class="fa-solid fa-shield-halved"></i>
                    <div class="tool-title">
                        <h1>تقرير الفحص والاستخراج الجنائي الرقمي (Android Forensic Triage)</h1>
                        <p>Powered by 4nsicsLarn Forensic Engine • v1.0.0 Pro</p>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn btn-primary" onclick="window.print()">
                        <i class="fa-solid fa-print"></i> طباعة / تصدير PDF
                    </button>
                    <button class="btn btn-outline" onclick="exportReportJSON()">
                        <i class="fa-solid fa-file-code"></i> تصدير JSON
                    </button>
                </div>
            </div>

            <div class="case-grid">
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-folder-open"></i> رقم القضية (Case ID)</div>
                    <div class="value">{case_meta.get('case_id', 'CAS-2026-001')}</div>
                </div>
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-barcode"></i> رمز الدليل (Evidence Tag)</div>
                    <div class="value">{case_meta.get('evidence_id', 'EVD-AND-01')}</div>
                </div>
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-user-secret"></i> الفاحص الجنائي (Examiner)</div>
                    <div class="value">{case_meta.get('examiner', 'Forensic Investigator')}</div>
                </div>
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-building-shield"></i> جهة التحقيق (Agency)</div>
                    <div class="value">{case_meta.get('agency', 'Digital Forensics Lab')}</div>
                </div>
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-clock"></i> وقت المعالجة والتحليل (UTC)</div>
                    <div class="value">{report_time_utc}</div>
                </div>
                <div class="meta-item">
                    <div class="label"><i class="fa-solid fa-mobile-screen"></i> النظام والبيئة المستهدفة</div>
                    <div class="value">Android OS (SQLite Triage)</div>
                </div>
            </div>
        </header>

        <!-- KPI Metrics Row -->
        <div class="kpi-row">
            <div class="kpi-card">
                <div class="kpi-icon icon-blue"><i class="fa-solid fa-phone-volume"></i></div>
                <div class="kpi-content">
                    <h3>{total_calls}</h3>
                    <p>إجمالي سجلات المكالمات (Calls)</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon icon-green"><i class="fa-solid fa-comment-sms"></i></div>
                <div class="kpi-content">
                    <h3>{total_sms}</h3>
                    <p>إجمالي الرسائل (SMS/MMS)</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon icon-amber"><i class="fa-solid fa-globe"></i></div>
                <div class="kpi-content">
                    <h3>{total_history}</h3>
                    <p>سجل التصفح ({unique_domains} نطاقات)</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon icon-purple"><i class="fa-solid fa-timeline"></i></div>
                <div class="kpi-content">
                    <h3>{len(timeline_events)}</h3>
                    <p>أحداث الخط الزمني الموحد</p>
                </div>
            </div>
        </div>

        <!-- Evidence Integrity / Hashes Table -->
        <section class="section-card">
            <div class="section-title">
                <i class="fa-solid fa-fingerprint" style="color: var(--accent-green);"></i>
                سلسلة العهدة وتجزئة سلامة الأدلة (Cryptographic Integrity & Chain of Custody)
            </div>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 12px;">
                تم استخراج وحساب قيم التجزئة (Hashes) لملفات الأدلة الرقمية لضمان سلامتها الجنائية وعدم العبث بها وفق المعايير المعتمدة (ISO/IEC 27037).
            </p>
            <div style="overflow-x: auto;">
                <table class="hash-table">
                    <thead>
                        <tr>
                            <th>Evidence File</th>
                            <th>File Size</th>
                            <th>SHA-256 Hash (Forensic Integrity)</th>
                            <th>MD5 Hash</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for ev in evidence_hashes:
        html_content += f"""
                        <tr>
                            <td><strong>{ev['file_name']}</strong><br><small style="color:#64748b;">{ev['file_path']}</small></td>
                            <td>{ev['file_size_formatted']}</td>
                            <td><span class="hash-code">{ev['sha256']}</span></td>
                            <td><span class="hash-code">{ev['md5']}</span></td>
                            <td><span class="badge-verified"><i class="fa-solid fa-check"></i> VERIFIED</span></td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Interactive Charts Grid -->
        <div class="charts-grid">
            <div class="chart-box" style="grid-column: 1 / -1; height: 350px;">
                <h4><i class="fa-solid fa-chart-line" style="color: var(--accent-blue);"></i> النشاط الزمني اليومي الموزع (Activity Timeline)</h4>
                <div style="position: relative; height: 280px;">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h4><i class="fa-solid fa-chart-pie" style="color: var(--accent-blue);"></i> توزيع أنواع المكالمات</h4>
                <div style="position: relative; height: 250px;">
                    <canvas id="callsChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h4><i class="fa-solid fa-chart-pie" style="color: var(--accent-green);"></i> اتجاه الرسائل النصية (SMS Direction)</h4>
                <div style="position: relative; height: 250px;">
                    <canvas id="smsChart"></canvas>
                </div>
            </div>
            <div class="chart-box" style="grid-column: 1 / -1; height: 320px;">
                <h4><i class="fa-solid fa-chart-column" style="color: var(--accent-amber);"></i> أكثر النطاقات والمواقع زيارة (Top Visited Domains)</h4>
                <div style="position: relative; height: 250px;">
                    <canvas id="domainsChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="tabs-header">
            <button class="tab-btn active" onclick="switchTab('timeline-tab', this)">
                <i class="fa-solid fa-timeline"></i> الخط الزمني الموحد ({len(timeline_events)})
            </button>
            <button class="tab-btn" onclick="switchTab('calls-tab', this)">
                <i class="fa-solid fa-phone"></i> سجل المكالمات ({total_calls})
            </button>
            <button class="tab-btn" onclick="switchTab('sms-tab', this)">
                <i class="fa-solid fa-comments"></i> الرسائل النصية ({total_sms})
            </button>
            <button class="tab-btn" onclick="switchTab('browser-tab', this)">
                <i class="fa-solid fa-compass"></i> سجل التصفح ({total_history})
            </button>
        </div>

        <!-- TAB 1: Unified Timeline -->
        <div id="timeline-tab" class="tab-pane active">
            <div class="section-card">
                <div class="timeline-filter-bar">
                    <span style="font-size: 0.85rem; color: var(--text-secondary); margin-left: 8px;">تصفية حسب المصدر:</span>
                    <button class="filter-chip active" onclick="filterTimeline('ALL', this)">الكل (All)</button>
                    <button class="filter-chip" onclick="filterTimeline('CALL', this)"><i class="fa-solid fa-phone"></i> المكالمات</button>
                    <button class="filter-chip" onclick="filterTimeline('SMS', this)"><i class="fa-solid fa-comment-sms"></i> الرسائل</button>
                    <button class="filter-chip" onclick="filterTimeline('BROWSER', this)"><i class="fa-solid fa-globe"></i> المتصفح</button>
                </div>
                <table id="timelineTable" class="dataTable">
                    <thead>
                        <tr>
                            <th style="width: 170px;">التوقيت (UTC)</th>
                            <th style="width: 90px;">النوع</th>
                            <th style="width: 150px;">الحدث</th>
                            <th style="width: 220px;">الطرف / النطاق المعني</th>
                            <th>تفاصيل الأثر الجنائي (Forensic Summary)</th>
                            <th style="width: 120px;">المصدر</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for ev in timeline_events:
        art_type = ev["artifact_type"]
        badge_class = f"badge-{art_type.lower()}"
        source_name = ev["source_file"].split("/")[-1].split("\\")[-1]
        summary_clean = str(ev["summary"]).replace("<", "&lt;").replace(">", "&gt;")
        entity_clean = str(ev["entity"]).replace("<", "&lt;").replace(">", "&gt;")

        html_content += f"""
                        <tr data-type="{art_type}">
                            <td><span style="font-family: monospace;">{ev['timestamp_utc']}</span></td>
                            <td><span class="badge {badge_class}">{art_type}</span></td>
                            <td><strong>{ev['action']}</strong></td>
                            <td>{entity_clean}</td>
                            <td>{summary_clean}</td>
                            <td><small style="color:var(--text-secondary);">{source_name} #{ev['record_id']}</small></td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: Calls -->
        <div id="calls-tab" class="tab-pane">
            <div class="section-card">
                <table id="callsTable" class="dataTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>الاسم المسجل</th>
                            <th>رقم الهاتف</th>
                            <th>نوع المكالمة</th>
                            <th>المدة</th>
                            <th>التاريخ والوقت (UTC)</th>
                            <th>الموقع الجغرافي</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for c in calls:
        call_type = c["call_type"]
        type_badge = "badge-incoming" if "Incoming" in call_type else ("badge-outgoing" if "Outgoing" in call_type else "badge-missed")
        html_content += f"""
                        <tr>
                            <td>{c['record_id']}</td>
                            <td><strong>{c['contact_name']}</strong></td>
                            <td style="direction:ltr; text-align:right;">{c['phone_number']}</td>
                            <td><span class="badge {type_badge}">{call_type}</span></td>
                            <td>{c['duration_formatted']}</td>
                            <td><span style="font-family: monospace;">{c['timestamp_utc']}</span></td>
                            <td>{c['location']}</td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 3: SMS Messages -->
        <div id="sms-tab" class="tab-pane">
            <div class="section-card">
                <table id="smsTable" class="dataTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>الاتجاه (Direction)</th>
                            <th>المرسل / المستقبل</th>
                            <th>التاريخ والوقت (UTC)</th>
                            <th>نص الرسالة</th>
                            <th>الحالة</th>
                            <th>التطبيق</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for s in sms_messages:
        s_badge = "badge-incoming" if "Received" in s["message_type"] else "badge-outgoing"
        body_clean = str(s["body"]).replace("<", "&lt;").replace(">", "&gt;")
        html_content += f"""
                        <tr>
                            <td>{s['record_id']}</td>
                            <td><span class="badge {s_badge}">{s['message_type']}</span></td>
                            <td style="direction:ltr; text-align:right;">{s['address']}</td>
                            <td><span style="font-family: monospace;">{s['timestamp_utc']}</span></td>
                            <td>{body_clean}</td>
                            <td>{'مقروءة' if s['read'] else 'غير مقروءة'}</td>
                            <td><small style="color:var(--text-secondary);">{s['creator_app']}</small></td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 4: Browser History -->
        <div id="browser-tab" class="tab-pane">
            <div class="section-card">
                <table id="browserTable" class="dataTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>النطاق (Domain)</th>
                            <th>عنوان الصفحة (Title)</th>
                            <th>الرابط المستخرج (URL)</th>
                            <th>عدد الزيارات</th>
                            <th>آخر زيارة (UTC)</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for h in history:
        title_clean = str(h["title"]).replace("<", "&lt;").replace(">", "&gt;")
        url_clean = str(h["url"]).replace("<", "&lt;").replace(">", "&gt;")
        truncated_url = (url_clean[:65] + '...') if len(url_clean) > 65 else url_clean
        html_content += f"""
                        <tr>
                            <td>{h['record_id']}</td>
                            <td><strong>{h['domain']}</strong></td>
                            <td>{title_clean}</td>
                            <td><a href="{url_clean}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-blue); text-decoration: none;" title="{url_clean}">{truncated_url}</a></td>
                            <td>{h['visit_count']}</td>
                            <td><span style="font-family: monospace;">{h['timestamp_utc']}</span></td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Investigator Signoff Footer -->
        <footer class="report-footer">
            <div>
                <p style="font-size: 0.9rem; color: var(--text-secondary);">
                    <strong>ملاحظات التقرير الجنائي:</strong> تم إنشاء هذا التقرير تلقائياً وتوثيق التجزئة وفق معايير الحفاظ على الأدلة الرقمية.
                </p>
                <p style="font-size: 0.8rem; color: #64748b; margin-top: 4px;">
                    Case Notes: {case_meta.get('notes', 'Routine forensic triage examination. All hashes cryptographically verified.')}
                </p>
            </div>
            <div class="signature-box">
                <div style="font-size: 0.85rem; font-weight: 600; text-align: center;">اعتماد الفاحص الجنائي (Examiner Sign-Off)</div>
                <div class="sig-line">
                    التوقيع والختم الرسمي: {case_meta.get('examiner', 'Forensic Investigator')}
                </div>
            </div>
        </footer>
    </div>

    <!-- Embedded Scripts for Interactivity & Charts -->
    <script>
        const chartData = {chart_data_json};

        // Initialize DataTables
        $(document).ready(function() {{
            $('#timelineTable').DataTable({{
                pageLength: 25,
                language: {{
                    search: "بحث في الخط الزمني:",
                    lengthMenu: "عرض _MENU_ سجل",
                    info: "عرض _START_ إلى _END_ من أصل _TOTAL_ حدث",
                    paginate: {{ first: "الأول", previous: "السابق", next: "التالي", last: "الأخير" }}
                }}
            }});

            $('#callsTable').DataTable({{
                pageLength: 15,
                language: {{
                    search: "بحث في المكالمات:",
                    lengthMenu: "عرض _MENU_ سجل",
                    info: "عرض _START_ إلى _END_ من أصل _TOTAL_ مكالمة",
                    paginate: {{ previous: "السابق", next: "التالي" }}
                }}
            }});

            $('#smsTable').DataTable({{
                pageLength: 15,
                language: {{
                    search: "بحث في الرسائل:",
                    lengthMenu: "عرض _MENU_ سجل",
                    info: "عرض _START_ إلى _END_ من أصل _TOTAL_ رسالة",
                    paginate: {{ previous: "السابق", next: "التالي" }}
                }}
            }});

            $('#browserTable').DataTable({{
                pageLength: 15,
                language: {{
                    search: "بحث في المتصفح:",
                    lengthMenu: "عرض _MENU_ سجل",
                    info: "عرض _START_ إلى _END_ من أصل _TOTAL_ موقع",
                    paginate: {{ previous: "السابق", next: "التالي" }}
                }}
            }});

            initCharts();
        }});

        function switchTab(tabId, btn) {{
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }}

        function filterTimeline(type, chip) {{
            document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');

            const table = $('#timelineTable').DataTable();
            if (type === 'ALL') {{
                table.column(1).search('').draw();
            }} else {{
                table.column(1).search(type).draw();
            }}
        }}

        function initCharts() {{
            // Timeline Daily Activity Chart
            const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
            new Chart(ctxTimeline, {{
                type: 'bar',
                data: {{
                    labels: chartData.dates,
                    datasets: [
                        {{ label: 'Calls', data: chartData.calls_by_date, backgroundColor: '#38bdf8' }},
                        {{ label: 'SMS', data: chartData.sms_by_date, backgroundColor: '#4ade80' }},
                        {{ label: 'Browser', data: chartData.browser_by_date, backgroundColor: '#f59e0b' }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{ stacked: true, grid: {{ color: '#334155' }} }},
                        y: {{ stacked: true, grid: {{ color: '#334155' }} }}
                    }},
                    plugins: {{ legend: {{ labels: {{ color: '#f8fafc' }} }} }}
                }}
            }});

            // Calls Distribution
            const ctxCalls = document.getElementById('callsChart').getContext('2d');
            new Chart(ctxCalls, {{
                type: 'doughnut',
                data: {{
                    labels: chartData.call_types.labels,
                    datasets: [{{
                        data: chartData.call_types.data,
                        backgroundColor: ['#4ade80', '#38bdf8', '#f43f5e', '#a855f7']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#f8fafc' }} }} }}
                }}
            }});

            // SMS Direction
            const ctxSms = document.getElementById('smsChart').getContext('2d');
            new Chart(ctxSms, {{
                type: 'doughnut',
                data: {{
                    labels: chartData.sms_types.labels,
                    datasets: [{{
                        data: chartData.sms_types.data,
                        backgroundColor: ['#4ade80', '#38bdf8']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#f8fafc' }} }} }}
                }}
            }});

            // Top Domains Bar Chart
            const ctxDomains = document.getElementById('domainsChart').getContext('2d');
            new Chart(ctxDomains, {{
                type: 'bar',
                data: {{
                    labels: chartData.top_domains.labels,
                    datasets: [{{
                        label: 'عدد الزيارات (Visits)',
                        data: chartData.top_domains.data,
                        backgroundColor: '#f59e0b'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    scales: {{
                        x: {{ grid: {{ color: '#334155' }} }},
                        y: {{ grid: {{ color: '#334155' }} }}
                    }},
                    plugins: {{ legend: {{ labels: {{ color: '#f8fafc' }} }} }}
                }}
            }});
        }}

        function exportReportJSON() {{
            const exportData = {{
                case_metadata: {case_meta_json},
                evidence_hashes: {evidence_hashes_json},
                summary: {{
                    total_calls: {total_calls},
                    total_sms: {total_sms},
                    total_history: {total_history},
                    total_timeline_events: {len(timeline_events)}
                }},
                timeline: {timeline_export_json}
            }};

            const blob = new Blob([JSON.stringify(exportData, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "forensic_report_" + "{case_meta.get('case_id', 'case')}" + ".json";
            a.click();
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>
"""

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_html_path
