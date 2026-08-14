# FileSentinel — Golden Multi-Format End-to-End Audit Dataset

## Overview
The **Golden Audit Dataset** is the canonical, deterministic validation suite for FileSentinel's automated audit compliance engine. It proves end-to-end correctness across the entire production pipeline:

$$\text{Discovery} \longrightarrow \text{Format Extraction} \longrightarrow \text{Evidence Matching} \longrightarrow \text{Entity Resolution} \longrightarrow \text{Audit Evaluation}$$

### Core Invariants & Verification Rules
1. **Production Pipeline Execution**: All documents are read from disk and processed directly through real file extractors (`PDFExtractor`, `DOCXExtractor`, `XLSXExtractor`, `PPTXExtractor`, `CSVExtractor`, `TXTExtractor`). No document extraction is mocked or bypassed.
2. **Deterministic & Offline**: The suite requires zero internet connectivity or external API keys to execute.
3. **100% Synthetic Data**: All identifiers (GSTIN, PAN, Agent IDs, Employee IDs, names, addresses) are purely synthetic.
4. **Comprehensive Format Coverage**: Includes real binary files across 6 major enterprise document formats:
   - **PDF** (Portable Document Format)
   - **DOCX** (Office Open XML Word Document)
   - **XLSX** (Office Open XML Spreadsheet)
   - **PPTX** (Office Open XML Presentation)
   - **CSV** (Comma-Separated Values)
   - **TXT** (Structured UTF-8 Text Records)

---

## Synthetic Person Entities & Scenarios

### Primary Synthetic Entity: John Synthetic
- **Name**: `John Synthetic`
- **Agent ID**: `AG-GOLD-001`
- **Employee ID**: `EMP-GOLD-001`
- **Associated Evidence**:
  - `DRA_Certificate_John_Synthetic.pdf` (DRA Passed Certificate)
  - `Police_Verification_Certificate_John_Synthetic.txt` (Police Clearance Certificate)
  - `Agency_ID_Card_Issue_Register.txt` (Agency ID & Field Endorsement Badge)
  - `Refresher_Training_Attendance_2026.xlsx` (Mandatory Refresher Training)
  - `Agent_Onboarding_KYC_Verification.docx` (Authenticated KYC Dossier)
- **Expected Outcome**: Resolved into a unified, high-confidence primary entity.

### Secondary Synthetic Entity: Jane Synthetic
- **Name**: `Jane Synthetic`
- **Agent ID**: `AG-GOLD-002`
- **Employee ID**: `EMP-GOLD-002`
- **Associated Evidence**:
  - `Police_Verification_Receipt_Jane_Synthetic.txt` (Applied Proof of PV)
  - `Agency_ID_Card_Issue_Register.txt` (Agency ID & Field Endorsement Badge)
  - `Refresher_Training_Attendance_2026.xlsx` (Training Attendance Log)
  - `Agent_Onboarding_KYC_Verification.docx` (Authenticated KYC Dossier)
- **Expected Outcome**: Resolved into a distinct secondary entity with no false cross-contamination.

### Intentional Identity Conflict Case
- **File**: `Conflicting_Police_Verification_Jane_Synthetic.txt`
- **Scenario**: Document declares Employee Name `Jane Synthetic` while specifying Agent ID `AG-GOLD-001` (which belongs to `John Synthetic`).
- **Expected Outcome**: Flagged as `MULTIPLE_NAMES_FOR_IDENTIFIER` conflict by `EntityResolver`. Overall session status routes to `NEEDS_REVIEW`.

---

## Negative & Edge Test Cases

| Case | Document | Target Parameter | Tested Hardening Feature | Expected Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Case 1: Filename Spoofing** | `GST_Policy_Spoofed_Filename.pdf` | `ZTI-001` | Content-body validation prevents filename keyword from passing without GSTIN | Candidate flagged as filename-only match; Status: `REVIEW` |
| **Case 2: Generic Keyword Match** | `Generic_PF_ESIC_Policy_Keyword_Only.txt` | `IPM-001` | Domain structured validation enforces code/registration presence | Generic keyword match fails structured validation |
| **Case 3: Expired Document** | `Expired_Insurance_Policy_Sample.pdf` | `IPM-004` | `DateEvaluator` safe date extraction & comparison against audit date | Correctly flags expired policy ending 2026-03-31 |
| **Case 4: Recency Evaluation** | `Fire_Safety_Evacuation_Drill_Report_2026.pptx` | `IPM-008` | Recency comparison within 365 days of audit date (2026-08-14) | Drill conducted on 2026-06-01 is verified as `PASS` |
| **Case 5: Policy vs. Implementation** | `Endpoint_USB_Security_Policy.docx` + `DLP_GPO_Removable_Storage_Export.csv` | `ZTI-008` | Compound policy + implementation requirement | Verified both components exist -> `PASS` |
| **Case 6: Policy Only Review** | `Snipping_Tool_Restriction_Policy.docx` | `GCI-006` | Policy document alone cannot pass technical restriction | Policy identified without GPO export -> Status: `REVIEW` |

---

## Running the Golden Audit Suite

```bash
# Run the complete test suite including Golden Audit
npm test

# Or run the Golden Audit test suite directly
npx tsx tests/golden-audit/golden-audit-test.ts
```

### Directory Structure
```
tests/golden-audit/
├── documents/                     # 37 Real multi-format synthetic files
│   ├── *.pdf                      # Binary PDF documents
│   ├── *.docx                     # Binary OOXML Word documents
│   ├── *.xlsx                     # Binary OOXML Excel workbooks
│   ├── *.pptx                     # Binary OOXML Presentations
│   ├── *.csv                      # CSV structured exports
│   └── *.txt                      # Structured UTF-8 text records
├── dataset-manifest.json          # Manifest indexing all 37 files and purposes
├── expected-results.json          # Target compliance outcomes and entity expectations
├── generate-dataset.ts            # Deterministic generator script
├── golden-audit-test.ts           # End-to-end test runner verifying the pipeline
└── README.md                      # Documentation (this file)
```
