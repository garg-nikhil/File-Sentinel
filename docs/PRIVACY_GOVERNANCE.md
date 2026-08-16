# FileSentinel — Privacy-First Data Governance & Architecture

FileSentinel is architected around a strict local-first data processing paradigm:

```
SCAN LOCAL. STORE DOCUMENTS LOCAL. TRANSMIT MINIMUM METADATA.
```

---

## 1. Formal Data Classification Model

Every piece of data processed or stored by FileSentinel falls into one of three strict classifications:

### Category A: Local-Only Sensitive Data (NEVER TRANSMITTED)
* **Document Contents**: Full binary files (`.xlsx`, `.csv`, `.docx`, `.pdf`, `.txt`, `.pptx`).
* **Extracted Full Text & OCR**: Intermediate in-memory and SQLite-cached text streams.
* **Personally Identifiable Information (PII)**: Full individual names, employee names, customer names.
* **National & Tax Identifiers**: Indian PAN (`[A-Z]{5}[0-9]{4}[A-Z]`), Aadhaar numbers, GSTIN (`[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}`).
* **Contact Data & Identifiers**: Phone numbers, email addresses, employee IDs, bank account numbers, IFSC codes.
* **Compliance Certification Credentials**: DRA certificate numbers, police verification IDs.
* **Evidence Context Snippets**: Sentence-level quotes containing matching text.

**Storage**: Local SQLite database (`filesentinel.db`) ONLY.  
**Transmission Policy**: `NEVER_TRANSMIT`. Excluded unconditionally from all telemetry, analytics, and crash reports.

---

### Category B: Telemetry-Safe Metadata (OPT-IN MINIMAL AGGREGATE)
Transmitted only when **Scan Statistics** toggle is `ON`. Used for organization licensing validation, customer operational dashboards, and software quality assurance.

* **Identifiers**: Anonymous scan UUID, Tenant Org ID, Operator User ID, Machine Device ID.
* **Timestamps & Performance**: Scan start/end timestamps, scan duration in milliseconds.
* **Coarse Counters**: Total files discovered, files processed, supported files, failed files.
* **Compliance & Risk Statistics**: Overall compliance score percentage, critical/high/medium/low severity issue counts.
* **Software Versioning**: Application version, static scanner engine version, regulatory checklist release number.

**Storage**: Local SQLite Queue + Secure Cloud Tenant Telemetry Database.  
**Transmission Policy**: `AGGREGATE_TELEMETRY_ALLOWED` (Opt-in via Settings).

---

### Category C: Optional Cloud Evidence (EXPLICIT USER ACTION ONLY)
Files and evidence artifacts transmitted to cloud quarantine or cloud backup **ONLY** upon explicit, interactive operator confirmation.

* **Audit Artifacts**: Specific compliance evidence reports or flagged files explicitly selected for Cloud Quarantine.
* **Integrity Proofs**: SHA-256 cryptographic checksums verifying remote bit-for-bit authenticity.

**Storage**: Cloud Object Vault + Local SQLite Audit Mirror.  
**Transmission Policy**: `EXPLICIT_USER_ACTION_ONLY`.

---

## 2. Privacy Settings & Boundary Controls

FileSentinel provides four primary hardware-level toggles in the Settings view:

1. **Document Content**: `LOCAL ONLY` (Fixed hardware guarantee — no silent background uploads).
2. **Scan Statistics**: `ON / OFF` (Controls transmission of Category B aggregate telemetry metrics).
3. **Crash Diagnostics**: `ON / OFF` (Anonymous exception stack traces without file paths or document content).
4. **Cloud Evidence Backup**: `ON / OFF` (Enables manual staging to cloud quarantine).
5. **Debug Filename Telemetry**: `OFF` by default (Includes sanitized base filenames in telemetry payloads; opt-in only).

---

## 3. Zero-Leakage Telemetry Debugger & Inspector

FileSentinel includes a live **Telemetry Debugger** (`GET /api/privacy/telemetry-preview/:scan_id`) allowing compliance officers and security teams to preview and inspect the exact JSON payload before any data leaves the host workstation.

The inspector runs recursive pattern matching across all fields to guarantee that 0 Category A sensitive fields are present.

---

## 4. Configurable Data Retention & Local Durability Guarantee

* **Configurable Cloud Retention**: Cloud metadata can be configured for automatic purge at 30, 90, 180, 365 days, or Indefinite.
* **Local Customer Durability Guarantee**: Cloud metadata purges or subscription tier expirations **NEVER** delete or alter local customer scan history, audit records, or evaluated compliance parameters in `filesentinel.db`.

---

## 5. Regulatory & Compliance Support Statement

FileSentinel is engineered to support organizational compliance with data protection laws including the Digital Personal Data Protection (DPDP) Act 2023, Information Technology Act 2000, and GDPR data minimization tenets. The software provides technical guardrails, privacy isolation, and architectural controls to support customer compliance programs; it does not claim automatic or official regulatory certification.
