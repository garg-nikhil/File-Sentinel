# FileSentinel — Local-First File Security & Compliance Scanner

FileSentinel is a local-first file security, data loss prevention (DLP), and compliance scanning application. It scans local computer files (`XLSX`, `CSV`, `DOCX`, `TXT`, `PPTX`, `PDF`), extracts content and metadata, evaluates findings against customizable security rules, optionally uses Google Gemini 3.6 Flash for semantic analysis, generates risk scores, and provides a secure cloud quarantine workflow with SHA-256 verified local deletion.

---

## 1. Core Architecture & Product Principles

1. **Deterministic Application Layer**:
   - File discovery, parsing, hashing (`SHA-256`), extraction, DLP rule evaluation, risk scoring, quarantine staging, and local file deletion are strictly controlled by the local deterministic application engine.
   - Files are NEVER executed during scanning (no macro execution, no embedded script invocation, no hyperlink execution).

2. **AI Assistance (Gemini 3.6 Flash)**:
   - Used optionally for semantic classification (`RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`), document summaries, and remediation recommendations.
   - Gemini cannot directly delete, modify, or quarantine files.

3. **Verified Cloud Quarantine & Safe Local Removal**:
   - Local file deletion **ONLY** occurs after:
     1. SHA-256 pre-upload checksum verification.
     2. Upload to Cloud Quarantine storage.
     3. Verification of remote cloud object presence and SHA-256 hash match.
   - If any step fails, the local file remains **100% untouched**.

---

## 2. Technology Stack

- **Backend**: Express + TypeScript (`server.ts`, Node.js 22, `node:sqlite`)
- **Frontend**: React 19, Vite, Tailwind CSS v4, Lucide Icons
- **AI Integration**: `@google/genai` (Gemini 3.6 Flash)
- **Database**: SQLite (`filesentinel.db`)

---

## 3. Supported File Formats

- `.xlsx` — Excel Spreadsheets (detects hidden sheets, formulas, external links)
- `.csv` — Comma-Separated Values (payroll, credit cards, bank account data)
- `.docx` — Word Documents (embedded OLE objects, external relationships)
- `.txt` — Plain Text (AWS keys, private keys, JWTs, database connection strings)
- `.pptx` — PowerPoint Presentations (speaker notes, hidden slides)
- `.pdf` — PDF Documents (PDF JavaScript actions, internal network references)

---

## 4. Getting Started & Development

### Installation & Server Execution

```bash
# Install dependencies
npm install

# Build backend and frontend assets
npm run build

# Start production server
npm run start
```

### Development Mode

```bash
npm run dev
```

The application runs locally on **`http://localhost:3000`**.

---

## 5. REST API Endpoints

- `GET /api/health` — Engine health check and SQLite database status.
- `GET /api/dashboard/stats` — High-level telemetry, risk score breakdown, and recent findings.
- `POST /api/scans` — Trigger recursive folder discovery and static scan.
- `GET /api/scans/:id/progress` — Real-time scan telemetry.
- `GET /api/files` — List scanned files with risk scores and classification tags.
- `GET /api/files/:id` — View full file details, SHA-256, findings, and extracted preview.
- `POST /api/files/:id/analyze-ai` — Trigger Gemini 3.6 Flash semantic analysis.
- `GET /api/findings` — Global list of normalized DLP rule triggers.
- `GET /api/rules` — Retrieve configurable security rules.
- `PUT /api/rules/:id/toggle` — Enable/disable individual rules.
- `POST /api/quarantine/:id/upload-and-remove` — Verified cloud quarantine and local deletion.

---

## 6. Verification & Security Protections

- **Non-Execution**: Static file inspection only.
- **Privacy & Redaction**: Matches in evidence snippets are masked by default.
- **Audit Logging**: Immutable event log tracking scan initialization, AI evaluation, and verified removals.
