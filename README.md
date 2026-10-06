# 4nsicsLarn - Android Forensic Triage Tool
**أداة الفحص والاستخراج الجنائي الرقمي لهواتف أندرويد**

أداة جنائية متطورة ومكتوبة بلغة Python لفحص وتحليل قواعد بيانات SQLite المستخرجة من أجهزة أندرويد (Android OS)، وتوثيق سلامة الأدلة وحساب التجزئة المشفرة (SHA-256 / MD5)، وتوليد خط زمني جنائي موحد (Unified Chronological Timeline)، وإنشاء تقرير جنائي رقمي تفاعلي كامل بصيغة HTML مدعوم بالجداول والرسوم البيانية وتفاصيل الفاحص وسلسلة العهدة (Chain of Custody).

---

## 🌟 المميزات الرئيسية (Core Features)

1. **تحليل قواعد بيانات أندرويد المستخرجة (Android SQLite Parsing):**
   - **سجل المكالمات (Call Logs):** قراءة `calllog.db` و `contacts2.db` (جدول `calls`) واستخراج الأرقام، الأسماء، التوقيت، المدة، نوع الاتصال (صادرة، واردة، فائتة، مرفوضة)، والموقع الجغرافي.
   - **الرسائل النصية (SMS/MMS):** قراءة `mmssms.db` (جدول `sms`) وتحديد الاتجاه (مرسلة / واردة)، حالة القراءة، نص الرسالة، والمعرّف التسلسلي.
   - **سجل التصفح (Chrome Web History):** قراءة قاعدة بيانات `History` لمتصفح Chrome/Chromium واستخراج الروابط (URLs)، عناوين الصفحات، النطاقات (Domains)، عدد الزيارات، وتوقيت آخر زيارة عبر تحويل توقيت WebKit Microseconds بدقة.

2. **ضمان سلامة الأدلة الرقمية (Cryptographic Integrity):**
   - حساب فوري لتجزئة **SHA-256** و **MD5** لكل قاعدة بيانات مستخرجة فور البدء.
   - إنشاء ملف بيان رسمي للتجزئة بصيغة `hashes_<CASE_ID>.sha256` معتمد جنائياً لضمان عدم التلاعب (Anti-Tampering).

3. **الخط الزمني الجنائي الموحد (Unified Chronological Timeline):**
   - توحيد جميع الأحداث الرقمية (مكالمة، رسالة، تصفح موقع) في خط زمني واحد بدقة التوقيت العالمي (UTC).
   - تصفية متقدمة حسب نوع الأثر الجنائي والبحث اللحظي.

4. **تقرير جنائي تفاعلي متكامل (Interactive HTML Forensic Report):**
   - واجهة عصرية متوافقة مع اللغة العربية والإنجليزية وتعمل حتى دون إنترنت.
   - لوحة إحصائية ومؤشرات أداء رئيسية (KPI Cards).
   - رسوم بيانية تفاعلية (Chart.js) لتوزيع النشاط اليومي، أنواع المكالمات، اتجاه الرسائل، وأكثر النطاقات زيارة.
   - جداول بيانات قابلة للبحث والفرز والترقيم (DataTables).
   - جاهز للطباعة والتصدير المباشر كملف PDF (`window.print()`).
   - تصدير كامل للبيانات بصيغة JSON.
   - توثيق بيانات القضية، اسم الفاحص الجنائي، جهة التحقيق، ومساحة التوقيع الرسمي (Examiner Sign-Off).

---

## 📁 هيكلية المشروع (Project Structure)

```text
4nsicsLarn/
├── 4nsicsLarn.py             # السكريبت والواجهة الرئيسية للأداة (CLI Engine)
├── parsers.py                # وحدات قراءة وتحليل قواعد SQLite المختلفة
├── hasher.py                 # وحدة التجزئة المشفرة وسلسلة العهدة (SHA-256 / MD5)
├── timeline.py               # وحدة معالجة وتوحيد الخط الزمني والإحصائيات
├── html_reporter.py          # وحدة بناء وتوليد التقرير الجنائي التفاعلي (HTML)
├── mock_data_generator.py    # مولد بيانات تجريبية واقعية لأغراض الاختبار والتدريب
└── README.md                 # الدليل التوثيقي
```

---

## 🚀 طريقة التثبيت والاستخدام (Usage Guide)

### 1. المتطلبات:
- Python 3.8 أو أحدث (لا تتطلب مكتبات خارجية معقدة؛ تعتمد على المكتبات القياسية `sqlite3`, `hashlib`, `urllib`, `argparse`).

### 2. التشغيل في الوضع التجريبي (Demo Mode):
لتجربة الأداة فوراً وإنشاء قواعد بيانات تجريبية واقعية وتشغيل الفحص:
```bash
python 4nsicsLarn.py --demo --case-id CAS-2026-001 --examiner "المحقق الجنائي أحمد" --agency "مختبر الأدلة الرقمية"
```

### 3. فحص أدلة حقيقية مستخرجة (Live Investigation):
إذا قمت باستخراج قواعد البيانات من هاتف مشتبه به إلى مجلد `extracted_evidence`:
```bash
python 4nsicsLarn.py -i ./extracted_evidence -o ./case_output --case-id CAS-SA-2026-881 --evidence-id EVD-01 --examiner "Capt. Al-Harbi" --agency "Cyber Forensics Unit"
```

### خيارات سطر الأوامر (Command Line Arguments):
| المعامل | الوصف | القيمة الافتراضية |
| :--- | :--- | :--- |
| `-i`, `--input` | مسار المجلد الذي يحتوي على قواعد بيانات SQLite المستخرجة | مطلوب (أو `--demo`) |
| `-o`, `--output` | مسار حفظ التقرير والنتائج وملفات التجزئة | `forensic_output` |
| `--case-id` | رقم القضية الجنائية | `CAS-2026-0491` |
| `--evidence-id` | رمز الدليل الرقمي (Evidence Tag) | `EVD-AND-01` |
| `--examiner` | اسم أو رتبة الفاحص الجنائي | `Digital Forensics Investigator` |
| `--agency` | الجهة المحققة / المختبر الجنائي | `Cyber Crime & Forensics Unit` |
| `--notes` | ملاحظات التحقيق والقرائن | نص اختياري |
| `--demo` | توليد بيانات وهمية وفحصها فوراً | False |

---

## 📱 مسارات قواعد البيانات في نظام أندرويد (Evidence Acquisition Paths)

للمختصين الجنائيين، تتواجد قواعد البيانات عادة في المسارات التالية بعد الحصول على صلاحيات الجذر (Root) أو عبر الاستخراج المنطقي/المادي (ADB Backup / Physical Dump):

1. **سجل المكالمات (Call Logs):**
   - Android 6.0+: `/data/data/com.android.providers.contacts/databases/calllog.db`
   - الإصدارات القديمة: `/data/data/com.android.providers.contacts/databases/contacts2.db`
2. **الرسائل القصيرة (SMS/MMS):**
   - `/data/data/com.android.providers.telephony/databases/mmssms.db`
3. **متصفح كروم (Google Chrome History):**
   - `/data/data/com.android.chrome/app_chrome/Default/History`

**أمر استخراج سريع عبر ADB (في حال وجود صلاحيات root):**
```bash
adb shell "su -c 'cp /data/data/com.android.providers.contacts/databases/calllog.db /sdcard/'"
adb shell "su -c 'cp /data/data/com.android.providers.telephony/databases/mmssms.db /sdcard/'"
adb shell "su -c 'cp /data/data/com.android.chrome/app_chrome/Default/History /sdcard/'"
adb pull /sdcard/calllog.db ./evidence/
adb pull /sdcard/mmssms.db ./evidence/
adb pull /sdcard/History ./evidence/
```

---

## 📊 مخرجات الفحص (Output Artifacts)

عند اكتمال الفحص، يقوم السكريبت بتوليد الملفات التالية داخل مجلد المخرجات المحدد:
1. `forensic_report_<CASE_ID>.html`: التقرير التفاعلي الرئيسي الذي يحتوي على كامل التفاصيل والرسوم البيانية وسلسلة العهدة.
2. `hashes_<CASE_ID>.sha256`: ملف تجزئة SHA-256 القياسي لتوثيق سلامة الأدلة.
3. `triage_summary_<CASE_ID>.json`: ملف JSON مهيكل يحتوي على ملخص الفحص لاستيراده في منصات SIEM أو أنظمة التحليل الأخرى.
