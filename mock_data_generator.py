"""
4nsicsLarn - Mock Android Database Generator
Generates realistic SQLite databases for Android forensic testing:
  1. calllog.db / contacts2.db (Call logs)
  2. mmssms.db (SMS/MMS messages)
  3. History (Chrome browser history)
"""

import os
import sqlite3
import random
from datetime import datetime, timedelta

def unix_to_chrome_time(dt: datetime) -> int:
    """Converts a datetime to Chrome's WebKit timestamp (microseconds since Jan 1, 1601 UTC)."""
    epoch_start = datetime(1601, 1, 1)
    diff = dt - epoch_start
    return int(diff.total_seconds() * 1_000_000)

def unix_to_epoch_ms(dt: datetime) -> int:
    """Converts a datetime to Android Unix epoch milliseconds."""
    epoch_start = datetime(1970, 1, 1)
    diff = dt - epoch_start
    return int(diff.total_seconds() * 1000)

def generate_mock_calllog(output_path: str, base_time: datetime):
    if os.path.exists(output_path):
        os.remove(output_path)
    
    conn = sqlite3.connect(output_path)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE calls (
        _id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT,
        date INTEGER,
        duration INTEGER,
        type INTEGER,
        name TEXT,
        numbertype INTEGER,
        numberlabel TEXT,
        countryiso TEXT,
        geocoded_location TEXT,
        features INTEGER,
        subscription_id TEXT
    );
    """)

    contacts = [
        ("+966501234567", "سالم القحطاني", "Riyadh, SA"),
        ("+966559876543", "محمد الدوسري", "Dammam, SA"),
        ("+966543219876", "سارة المنصور", "Jeddah, SA"),
        ("+971501122334", "Unknown / Unknown Caller", "Dubai, AE"),
        ("+14155550199", "Tech Support (Suspect)", "California, US"),
        ("+966500001122", "مكتب العمل - المشرف", "Riyadh, SA"),
        ("+966567788990", "عبدالله العتيبي", "Mecca, SA"),
    ]

    # Types: 1=Incoming, 2=Outgoing, 3=Missed, 4=Voicemail, 5=Rejected, 6=Blocked
    call_records = []
    current_time = base_time - timedelta(days=5)

    for i in range(35):
        current_time += timedelta(hours=random.randint(1, 6), minutes=random.randint(2, 45))
        number, name, loc = random.choice(contacts)
        call_type = random.choices([1, 2, 3, 5], weights=[45, 35, 15, 5])[0]
        duration = random.randint(15, 840) if call_type in (1, 2) else 0
        date_ms = unix_to_epoch_ms(current_time)
        
        call_records.append((
            number, date_ms, duration, call_type, name, 1, "Mobile", "SA", loc, 0, "SIM1"
        ))

    cursor.executemany("""
    INSERT INTO calls (number, date, duration, type, name, numbertype, numberlabel, countryiso, geocoded_location, features, subscription_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, call_records)

    conn.commit()
    conn.close()
    print(f"[+] Generated mock call log at: {output_path} ({len(call_records)} records)")

def generate_mock_sms(output_path: str, base_time: datetime):
    if os.path.exists(output_path):
        os.remove(output_path)

    conn = sqlite3.connect(output_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE sms (
        _id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER,
        address TEXT,
        person INTEGER,
        date INTEGER,
        date_sent INTEGER,
        protocol INTEGER,
        read INTEGER,
        status INTEGER,
        type INTEGER,
        reply_path_present INTEGER,
        subject TEXT,
        body TEXT,
        service_center TEXT,
        locked INTEGER,
        sub_id INTEGER,
        error_code INTEGER,
        creator TEXT
    );
    """)

    sample_sms = [
        ("+966501234567", 1, "السلام عليكم أخي، هل وصلت إلى موقع الاجتماع؟"),
        ("+966501234567", 2, "وعليكم السلام، نعم وصلت وسأنتظركم في القاعة الرئيسية."),
        ("AlRajhiBank", 1, "تم إيداع مبلغ 12,500.00 ر.س في حسابك المنتهي بـ ****4321. الرصيد المتاح: 45,210.00 ر.س"),
        ("+966559876543", 1, "الملفات المطلوبة تم إرسالها عبر البريد المشفر، يرجى المراجعة فوراً."),
        ("+966559876543", 2, "تم الاستلام، جاري فحص المستندات الآن."),
        ("+14155550199", 1, "URGENT: Your account verification code is 894-231. Do not share with anyone."),
        ("+14155550199", 2, "Who is this? I did not request any code."),
        ("+971501122334", 1, "Please transfer the BTC wallet balance to the specified cold address."),
        ("+966543219876", 1, "صباح الخير، موعد تسليم التقرير الجنائي غداً الساعة 10 صباحاً."),
        ("+966543219876", 2, "صباح النور، التقرير شبه مكتمل وجاهز للطباعة."),
        ("Absher", 1, "رمز التحقق لتسجيل الدخول في منصة أبشر هو: 741258"),
        ("+966500001122", 1, "تمت الموافقة على طلب الإجازة للمدة المحددة."),
        ("+966567788990", 1, "أرسل لي الموقع الحالي عبر الخريطة."),
        ("+966567788990", 2, "تم، إحداثيات الموقع: 24.7136° N, 46.6753° E"),
    ]

    sms_records = []
    current_time = base_time - timedelta(days=6)

    for i in range(len(sample_sms)):
        current_time += timedelta(hours=random.randint(4, 14), minutes=random.randint(5, 30))
        sender, msg_type, body = sample_sms[i]
        date_ms = unix_to_epoch_ms(current_time)
        read_status = 1
        
        sms_records.append((
            i + 1, sender, 0, date_ms, date_ms, 0, read_status, -1, msg_type, 0, None, body, "+966500000000", 0, 1, 0, "com.google.android.apps.messaging"
        ))

    cursor.executemany("""
    INSERT INTO sms (thread_id, address, person, date, date_sent, protocol, read, status, type, reply_path_present, subject, body, service_center, locked, sub_id, error_code, creator)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sms_records)

    conn.commit()
    conn.close()
    print(f"[+] Generated mock SMS at: {output_path} ({len(sms_records)} records)")

def generate_mock_chrome_history(output_path: str, base_time: datetime):
    if os.path.exists(output_path):
        os.remove(output_path)

    conn = sqlite3.connect(output_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        title TEXT,
        visit_count INTEGER,
        typed_count INTEGER,
        last_visit_time INTEGER,
        hidden INTEGER
    );
    """)

    cursor.execute("""
    CREATE TABLE visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url INTEGER,
        visit_time INTEGER,
        from_visit INTEGER,
        transition INTEGER
    );
    """)

    sample_urls = [
        ("https://www.google.com/search?q=android+forensics+tools", "Google Search: android forensics tools", 5),
        ("https://github.com/4nsicsLarn/android-triage", "GitHub - 4nsicsLarn: Android Forensic Triage Tool", 8),
        ("https://www.google.com/search?q=how+to+wipe+sqlite+databases+permanently", "Google Search: how to wipe sqlite databases permanently", 2),
        ("https://duckduckgo.com/?q=tor+browser+apk+download", "DuckDuckGo: tor browser apk download", 3),
        ("https://blockchain.com/explorer/addresses/btc/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "Bitcoin Address bc1qar0srrr... Transaction History", 4),
        ("https://digital-forensics.sans.org/blog", "SANS Digital Forensics and Incident Response Blog", 6),
        ("https://mail.proton.me/login", "Proton Mail: Encrypted Email Service", 12),
        ("https://pastebin.com/raw/d8s8df9", "Pastebin Encrypted Paste Note", 1),
        ("https://maps.google.com/?q=24.7136,46.6753", "Google Maps: Riyadh Coordinates Locus", 3),
        ("https://www.alrajhibank.com.sa", "Al Rajhi Bank Online Portal", 7),
    ]

    urls_records = []
    visits_records = []
    current_time = base_time - timedelta(days=4)

    for idx, (url, title, vcount) in enumerate(sample_urls, start=1):
        current_time += timedelta(hours=random.randint(2, 9), minutes=random.randint(10, 40))
        chrome_time = unix_to_chrome_time(current_time)
        
        urls_records.append((idx, url, title, vcount, random.randint(0, 2), chrome_time, 0))
        visits_records.append((idx, idx, chrome_time, 0, 805306368))

    cursor.executemany("""
    INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, urls_records)

    cursor.executemany("""
    INSERT INTO visits (id, url, visit_time, from_visit, transition)
    VALUES (?, ?, ?, ?, ?)
    """, visits_records)

    conn.commit()
    conn.close()
    print(f"[+] Generated mock Chrome history at: {output_path} ({len(urls_records)} records)")

def create_mock_evidence_directory(target_dir: str):
    os.makedirs(target_dir, exist_ok=True)
    base_time = datetime(2026, 10, 5, 14, 30, 0)
    
    generate_mock_calllog(os.path.join(target_dir, "calllog.db"), base_time)
    generate_mock_sms(os.path.join(target_dir, "mmssms.db"), base_time)
    generate_mock_chrome_history(os.path.join(target_dir, "History"), base_time)
    print(f"[OK] All mock evidence databases created successfully in: {target_dir}")

if __name__ == "__main__":
    import sys
    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    test_dir = os.path.join(os.path.dirname(__file__), "mock_evidence")
    create_mock_evidence_directory(test_dir)
