"""
========================================================================================
 4nsicsLarn - Windows GUI (CustomTkinter)
 Android Mobile Digital Forensics Triage Tool - Graphical User Interface
========================================================================================
Modern Dark-themed GUI compatible with Windows 11 aesthetics.
Includes case metadata inputs, directory selectors, background worker threads,
live forensic console logging, and one-click HTML report launching.
"""

import os
import sys
import threading
import webbrowser
from datetime import datetime, timezone
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Adjust sys.path to ensure modules can be imported
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from hasher import compute_file_hashes
from parsers import parse_call_logs, parse_sms_messages, parse_chrome_history, detect_database_type
from timeline import build_unified_timeline, aggregate_timeline_stats
from html_reporter import generate_html_report
from mock_data_generator import create_mock_evidence_directory

# Set CustomTkinter theme and appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("4nsicsLarn - Android Forensic Triage Tool | واجهة الفحص الجنائي الرقمي")
        self.geometry("1120x800")
        self.minsize(980, 700)

        # State tracking
        self.last_report_path = None
        self.is_processing = False

        self._build_ui()

    def _build_ui(self):
        # Configure grid weights
        self.grid_columnconfigure(0, weight=4)  # Left controls
        self.grid_columnconfigure(1, weight=6)  # Right console
        self.grid_rowconfigure(1, weight=1)

        # ---------------- 1. Top Header Banner ----------------
        self.header_frame = ctk.CTkFrame(self, corner_radius=12, fg_color="#1e293b", border_width=1, border_color="#334155")
        self.header_frame.grid(row=0, column=0, columnspan=2, padx=16, pady=(16, 10), sticky="nsew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        header_subframe = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        header_subframe.pack(fill="x", padx=18, pady=12)

        title_lbl = ctk.CTkLabel(
            header_subframe,
            text="🛡️ 4nsicsLarn — Android Forensic Triage Tool",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title_lbl.pack(side="left")

        subtitle_lbl = ctk.CTkLabel(
            header_subframe,
            text="أداة الفحص الجنائي الرقمي لهواتف أندرويد • v1.0.0 Pro",
            font=ctk.CTkFont(size=13),
            text_color="#38bdf8"
        )
        subtitle_lbl.pack(side="left", padx=16)

        self.status_badge = ctk.CTkLabel(
            header_subframe,
            text="🟢 جاهز للعمل (READY)",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#064e3b",
            text_color="#34d399",
            corner_radius=8,
            padx=12,
            pady=4
        )
        self.status_badge.pack(side="right")

        # ---------------- 2. Left Column: Inputs & Controls ----------------
        self.left_scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.left_scroll.grid(row=1, column=0, padx=(16, 8), pady=(0, 16), sticky="nsew")

        # Card A: Case Metadata
        self.meta_card = ctk.CTkFrame(self.left_scroll, corner_radius=10, fg_color="#1e293b", border_width=1, border_color="#334155")
        self.meta_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            self.meta_card,
            text="📁 بيانات القضية والفاحص (Case Metadata)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 8))

        # Case ID
        ctk.CTkLabel(self.meta_card, text="رقم القضية (Case ID):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        self.entry_case_id = ctk.CTkEntry(self.meta_card, placeholder_text="e.g. CAS-2026-9041")
        self.entry_case_id.insert(0, f"CAS-AND-{datetime.now().strftime('%Y%m%d')}")
        self.entry_case_id.pack(fill="x", padx=16, pady=(2, 8))

        # Evidence ID
        ctk.CTkLabel(self.meta_card, text="رمز الدليل الرقمي (Evidence Tag):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        self.entry_evidence_id = ctk.CTkEntry(self.meta_card, placeholder_text="e.g. EVD-AND-01")
        self.entry_evidence_id.insert(0, "EVD-AND-01")
        self.entry_evidence_id.pack(fill="x", padx=16, pady=(2, 8))

        # Examiner Name
        ctk.CTkLabel(self.meta_card, text="اسم الفاحص الجنائي (Examiner Name):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        self.entry_examiner = ctk.CTkEntry(self.meta_card, placeholder_text="e.g. Capt. Forensic Investigator")
        self.entry_examiner.insert(0, "Digital Forensics Investigator")
        self.entry_examiner.pack(fill="x", padx=16, pady=(2, 8))

        # Agency
        ctk.CTkLabel(self.meta_card, text="جهة التحقيق (Agency / Unit):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        self.entry_agency = ctk.CTkEntry(self.meta_card, placeholder_text="e.g. Cyber Crime & Forensics Unit")
        self.entry_agency.insert(0, "Cyber Forensics Lab")
        self.entry_agency.pack(fill="x", padx=16, pady=(2, 14))

        # Card B: Directory Selectors
        self.dir_card = ctk.CTkFrame(self.left_scroll, corner_radius=10, fg_color="#1e293b", border_width=1, border_color="#334155")
        self.dir_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            self.dir_card,
            text="📂 مسارات الأدلة والمخرجات (Evidence Directories)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 8))

        # Input Directory
        ctk.CTkLabel(self.dir_card, text="مجلد قواعد البيانات المستخرجة (Input Folder):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        input_frame = ctk.CTkFrame(self.dir_card, fg_color="transparent")
        input_frame.pack(fill="x", padx=16, pady=(2, 8))
        self.entry_input_dir = ctk.CTkEntry(input_frame, placeholder_text="اختر مجلد الأدلة المستخرجة...")
        self.entry_input_dir.pack(side="left", fill="x", expand=True, padx=(0, 8))
        btn_browse_in = ctk.CTkButton(input_frame, text="تصفح...", width=80, command=self._browse_input_dir)
        btn_browse_in.pack(side="right")

        # Output Directory
        ctk.CTkLabel(self.dir_card, text="مجلد حفظ التقارير والنتائج (Output Folder):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(2, 0))
        output_frame = ctk.CTkFrame(self.dir_card, fg_color="transparent")
        output_frame.pack(fill="x", padx=16, pady=(2, 14))
        self.entry_output_dir = ctk.CTkEntry(output_frame, placeholder_text="مجلد المخرجات...")
        default_out = os.path.join(script_dir, "forensic_output")
        self.entry_output_dir.insert(0, default_out)
        self.entry_output_dir.pack(side="left", fill="x", expand=True, padx=(0, 8))
        btn_browse_out = ctk.CTkButton(output_frame, text="تصفح...", width=80, command=self._browse_output_dir)
        btn_browse_out.pack(side="right")

        # Card C: Action Operations
        self.action_card = ctk.CTkFrame(self.left_scroll, corner_radius=10, fg_color="#1e293b", border_width=1, border_color="#334155")
        self.action_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            self.action_card,
            text="⚡ إجراءات الفحص والتحليل (Forensic Actions)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 8))

        # Start Real Triage Button
        self.btn_start = ctk.CTkButton(
            self.action_card,
            text="🔍 بدء الفحص الجنائي الرقمي (Start Triage)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=42,
            command=self._start_real_triage
        )
        self.btn_start.pack(fill="x", padx=16, pady=(4, 8))

        # Run Demo Mode Button
        self.btn_demo = ctk.CTkButton(
            self.action_card,
            text="🧪 تشغيل الوضع التجريبي (Run Demo Mode)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            height=38,
            command=self._start_demo_mode
        )
        self.btn_demo.pack(fill="x", padx=16, pady=(0, 8))

        # Open Report in Browser Button
        self.btn_open_report = ctk.CTkButton(
            self.action_card,
            text="🌐 فتح التقرير الجنائي في المتصفح (Open Report)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#4f46e5",
            hover_color="#4338ca",
            height=38,
            state="disabled",
            command=self._open_report_in_browser
        )
        self.btn_open_report.pack(fill="x", padx=16, pady=(0, 8))

        # Clear Console Button
        btn_clear = ctk.CTkButton(
            self.action_card,
            text="🧹 مسح السجل (Clear Log)",
            font=ctk.CTkFont(size=12),
            fg_color="#334155",
            hover_color="#475569",
            height=32,
            command=self._clear_console
        )
        btn_clear.pack(fill="x", padx=16, pady=(0, 14))

        # ---------------- 3. Right Column: Live Console & Progress ----------------
        self.right_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e293b", border_width=1, border_color="#334155")
        self.right_frame.grid(row=1, column=1, padx=(8, 16), pady=(0, 16), sticky="nsew")
        self.right_frame.grid_rowconfigure(1, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)

        # Console Header
        console_hdr = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        console_hdr.grid(row=0, column=0, padx=16, pady=(12, 6), sticky="ew")

        ctk.CTkLabel(
            console_hdr,
            text="📟 سجل العمليات الجنائية اللحظي (Forensic Console)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        ).pack(side="left")

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.right_frame, height=8, corner_radius=4)
        self.progress_bar.grid(row=0, column=0, padx=16, pady=(40, 4), sticky="ew")
        self.progress_bar.set(0.0)

        # Console Textbox
        self.console_box = ctk.CTkTextbox(
            self.right_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#090d16",
            text_color="#e2e8f0",
            corner_radius=8,
            border_width=1,
            border_color="#334155"
        )
        self.console_box.grid(row=1, column=0, padx=16, pady=(6, 12), sticky="nsew")

        # Initial Welcome Message in Console
        self._log("================================================================================")
        self._log(" 4nsicsLarn - Android Forensic Triage Tool v1.0.0 Pro")
        self._log(" Cryptographic Hashes (SHA-256) • Unified Chronological Timeline • HTML Reports")
        self._log("================================================================================")
        self._log("[i] System initialized. Ready to begin forensic examination.")
        self._log("[i] Select evidence folder or click 'Run Demo Mode' to test.")

    # ---------------- UI Helper Methods ----------------
    def _browse_input_dir(self):
        folder = filedialog.askdirectory(title="اختر مجلد الأدلة المستخرجة (Input Evidence Folder)")
        if folder:
            self.entry_input_dir.delete(0, "end")
            self.entry_input_dir.insert(0, os.path.normpath(folder))
            self._log(f"[+] Selected Input Directory: {folder}")

    def _browse_output_dir(self):
        folder = filedialog.askdirectory(title="اختر مجلد حفظ النتائج (Output Directory)")
        if folder:
            self.entry_output_dir.delete(0, "end")
            self.entry_output_dir.insert(0, os.path.normpath(folder))
            self._log(f"[+] Selected Output Directory: {folder}")

    def _clear_console(self):
        self.console_box.delete("1.0", "end")
        self._log("[i] Console cleared.")

    def _log(self, message: str):
        self.console_box.insert("end", f"{message}\n")
        self.console_box.see("end")

    def _safe_log(self, message: str):
        """Thread-safe logging helper."""
        self.after(0, self._log, message)

    def _set_status(self, text: str, bg_color: str, text_color: str):
        self.status_badge.configure(text=text, fg_color=bg_color, text_color=text_color)

    def _set_processing_state(self, is_running: bool):
        self.is_processing = is_running
        if is_running:
            self.btn_start.configure(state="disabled")
            self.btn_demo.configure(state="disabled")
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self._set_status("⏳ جاري الفحص الجنائي...", "#78350f", "#fde047")
        else:
            self.btn_start.configure(state="normal")
            self.btn_demo.configure(state="normal")
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(1.0)
            self._set_status("🟢 اكتمل الفحص (FINISHED)", "#064e3b", "#34d399")
            if self.last_report_path and os.path.isfile(self.last_report_path):
                self.btn_open_report.configure(state="normal")

    # ---------------- Actions & Threading ----------------
    def _start_real_triage(self):
        if self.is_processing:
            return

        input_dir = self.entry_input_dir.get().strip()
        if not input_dir or not os.path.exists(input_dir):
            messagebox.showwarning("تنبيه", "يرجى اختيار مجلد أدلة موجود أولاً.")
            return

        output_dir = self.entry_output_dir.get().strip() or os.path.join(script_dir, "forensic_output")
        case_id = self.entry_case_id.get().strip() or "CAS-2026-001"
        evidence_id = self.entry_evidence_id.get().strip() or "EVD-AND-01"
        examiner = self.entry_examiner.get().strip() or "Examiner"
        agency = self.entry_agency.get().strip() or "Forensics Lab"

        thread = threading.Thread(
            target=self._execute_triage,
            args=(input_dir, output_dir, case_id, evidence_id, examiner, agency, False),
            daemon=True
        )
        thread.start()

    def _start_demo_mode(self):
        if self.is_processing:
            return

        output_dir = self.entry_output_dir.get().strip() or os.path.join(script_dir, "forensic_output")
        case_id = self.entry_case_id.get().strip() or f"CAS-DEMO-{datetime.now().strftime('%H%M%S')}"
        evidence_id = self.entry_evidence_id.get().strip() or "EVD-DEMO-01"
        examiner = self.entry_examiner.get().strip() or "Demo Forensic Examiner"
        agency = self.entry_agency.get().strip() or "Digital Forensics Unit"

        thread = threading.Thread(
            target=self._execute_triage,
            args=(None, output_dir, case_id, evidence_id, examiner, agency, True),
            daemon=True
        )
        thread.start()

    def _open_report_in_browser(self):
        if self.last_report_path and os.path.isfile(self.last_report_path):
            webbrowser.open(os.path.abspath(self.last_report_path))
            self._log(f"[+] Opened report in browser: {self.last_report_path}")
        else:
            messagebox.showinfo("تنبيه", "لم يتم العثور على ملف التقرير الجنائي.")

    # ---------------- Forensic Engine Core Execution ----------------
    def _execute_triage(self, input_dir, output_dir, case_id, evidence_id, examiner, agency, is_demo):
        self.after(0, self._set_processing_state, True)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            self._safe_log("\n" + "=" * 75)
            self._safe_log(f"[*] Starting Forensic Triage at: {now_str}")
            self._safe_log(f"    • Case ID:     {case_id}")
            self._safe_log(f"    • Evidence ID: {evidence_id}")
            self._safe_log(f"    • Examiner:    {examiner}")
            self._safe_log(f"    • Agency:      {agency}")
            self._safe_log("=" * 75)

            # Step 1: Demo setup if requested
            if is_demo:
                self._safe_log("\n[1/5] Generating mock Android SQLite evidence databases...")
                demo_source = os.path.join(output_dir, "mock_evidence_source")
                create_mock_evidence_directory(demo_source)
                input_dir = demo_source
                self.after(0, lambda: self.entry_input_dir.delete(0, "end"))
                self.after(0, lambda: self.entry_input_dir.insert(0, os.path.normpath(demo_source)))
                self._safe_log(f"      [OK] Mock evidence ready in: {demo_source}")

            os.makedirs(output_dir, exist_ok=True)

            # Step 2: Discover Evidence Files
            evidence_files = []
            if os.path.isfile(input_dir):
                evidence_files.append(os.path.abspath(input_dir))
            else:
                for root, _, files in os.walk(input_dir):
                    for file in files:
                        if file.endswith("-journal") or file.endswith("-wal") or file.endswith("-shm"):
                            continue
                        evidence_files.append(os.path.abspath(os.path.join(root, file)))

            if not evidence_files:
                self._safe_log(f"[-] Error: No files found to analyze in: {input_dir}")
                self.after(0, self._set_processing_state, False)
                return

            self._safe_log(f"\n[2/5] Discovered {len(evidence_files)} potential evidence file(s).")

            # Step 3: Compute Hashes (Chain of Custody)
            self._safe_log("\n[3/5] Computing cryptographic hashes (SHA-256 & MD5) for forensic integrity...")
            evidence_hashes = []
            manifest_lines = [
                f"# 4nsicsLarn Cryptographic Hash Manifest",
                f"# Generated: {now_str}",
                f"# Case ID: {case_id} | Evidence ID: {evidence_id}",
                f"# Examiner: {examiner}",
                "# " + "=" * 70,
                ""
            ]

            for fpath in evidence_files:
                try:
                    hash_info = compute_file_hashes(fpath)
                    evidence_hashes.append(hash_info)
                    manifest_lines.append(f"{hash_info['sha256']}  {hash_info['file_name']}")
                    self._safe_log(f"      [VERIFIED] {hash_info['file_name']} ({hash_info['file_size_formatted']})")
                    self._safe_log(f"                 SHA-256: {hash_info['sha256']}")
                except Exception as e:
                    self._safe_log(f"      [!] Error hashing {fpath}: {e}")

            manifest_path = os.path.join(output_dir, f"hashes_{case_id}.sha256")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write("\n".join(manifest_lines) + "\n")
            self._safe_log(f"      [+] Hash manifest saved: {os.path.basename(manifest_path)}")

            # Step 4: Parse Databases
            self._safe_log("\n[4/5] Parsing Android SQLite database tables...")
            all_calls = []
            all_sms = []
            all_history = []

            for fpath in evidence_files:
                db_type = detect_database_type(fpath)
                fname = os.path.basename(fpath)

                if db_type == "calls":
                    self._safe_log(f"      [+] Analyzing Call Logs database: {fname}")
                    calls = parse_call_logs(fpath)
                    all_calls.extend(calls)
                    self._safe_log(f"          -> Extracted {len(calls)} call record(s)")

                elif db_type == "sms":
                    self._safe_log(f"      [+] Analyzing SMS/MMS messages: {fname}")
                    sms_list = parse_sms_messages(fpath)
                    all_sms.extend(sms_list)
                    self._safe_log(f"          -> Extracted {len(sms_list)} SMS message(s)")

                elif db_type == "chrome":
                    self._safe_log(f"      [+] Analyzing Chrome Web History: {fname}")
                    hist = parse_chrome_history(fpath)
                    all_history.extend(hist)
                    self._safe_log(f"          -> Extracted {len(hist)} web browsing URL(s)")

            # Step 5: Timeline & Report Compilation
            self._safe_log("\n[5/5] Building Unified Chronological Timeline and compiling HTML report...")
            timeline_events = build_unified_timeline(all_calls, all_sms, all_history)
            timeline_stats = aggregate_timeline_stats(timeline_events)

            self._safe_log(f"      -> Total Unified Timeline events: {len(timeline_events)}")
            if timeline_events:
                self._safe_log(f"      -> Earliest Event: {timeline_stats['earliest_date']}")
                self._safe_log(f"      -> Latest Event:   {timeline_stats['latest_date']}")

            report_filename = f"forensic_report_{case_id}.html"
            report_path = os.path.join(output_dir, report_filename)

            case_meta = {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "examiner": examiner,
                "agency": agency,
                "notes": "Automated forensic triage performed via 4nsicsLarn GUI interface."
            }

            generate_html_report(
                case_meta=case_meta,
                evidence_hashes=evidence_hashes,
                calls=all_calls,
                sms_messages=all_sms,
                history=all_history,
                timeline_events=timeline_events,
                timeline_stats=timeline_stats,
                output_html_path=report_path
            )

            self.last_report_path = report_path
            self._safe_log("\n" + "=" * 75)
            self._safe_log(" [✓] FORENSIC EXAMINATION COMPLETED SUCCESSFULLY!")
            self._safe_log("=" * 75)
            self._safe_log(f"  • Total Call Records:     {len(all_calls)}")
            self._safe_log(f"  • Total SMS Messages:     {len(all_sms)}")
            self._safe_log(f"  • Total Web History URLs: {len(all_history)}")
            self._safe_log(f"  • Total Timeline Events:  {len(timeline_events)}")
            self._safe_log(f"  • Interactive Report:     {os.path.abspath(report_path)}")
            self._safe_log("=" * 75)
            self._safe_log("[+] Click 'Open Report' to inspect results in your browser.\n")

        except Exception as e:
            self._safe_log(f"\n[!] Unexpected Error during examination: {str(e)}")
            import traceback
            self._safe_log(traceback.format_exc())
        finally:
            self.after(0, self._set_processing_state, False)

if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()
