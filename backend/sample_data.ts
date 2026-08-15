import fs from 'node:fs';
import path from 'node:path';
import * as XLSX from 'xlsx';
import JSZip from 'jszip';

export async function ensureSampleFilesExist(baseDir: string = './sample-files'): Promise<string[]> {
  const folders = [
    path.join(baseDir, 'finance'),
    path.join(baseDir, 'dev-keys'),
    path.join(baseDir, 'hr'),
    path.join(baseDir, 'security'),
    path.join(baseDir, 'public'),
    path.join(baseDir, 'reports'),
    path.join(baseDir, 'audit')
  ];

  for (const f of folders) {
    if (!fs.existsSync(f)) {
      fs.mkdirSync(f, { recursive: true });
    }
  }

  // --- SYNTHETIC AUDIT SAMPLE DOCUMENTS ---
  const auditDir = path.join(baseDir, 'audit');

  // ZTI-001: GST Certificate
  fs.writeFileSync(
    path.join(auditDir, 'GST_Registration_Certificate.txt'),
    `FORM GST REG-06 - GOVERNMENT OF INDIA
REGISTRATION CERTIFICATE
GSTIN: 27AAACF1234F1Z5
Legal Name: Zenith Telecalling & Collection Services Pvt Ltd
Trade Name: Zenith Collections
Date of Issue: 15/01/2024
Status: ACTIVE
Agency Board Details: Board of Directors - John Smith, Alice Miller`,
    'utf-8'
  );

  // ZTI-002: Access Control Biometric Log
  fs.writeFileSync(
    path.join(auditDir, 'Biometric_Access_Control_Config.txt'),
    `AGENCY ACCESS CONTROL & BIOMETRIC SYSTEM CONFIGURATION
System: BioEntry W2 Fingerprint & Card Reader System
Physical Security: Badge reader & Door Access Controller active
Access Policy: Restricts entrance to authorized lending staff only
Implementation Log: Daily biometric door entry scans enabled. Door Access Controller IP: 192.168.10.15`,
    'utf-8'
  );

  // ZTI-003: Dedicated Workspace Allocation
  fs.writeFileSync(
    path.join(auditDir, 'Phone_Lending_Dedicated_Workspace.txt'),
    `PHONE LENDING BUSINESS WORKSPACE ALLOCATION DECREE
Dedicated Bay: Bay 4 - Segregated Phone Lending Unit
System Allocation: Laptops SYS-PL-001 through SYS-PL-050
Physical Segregation: Keycard locked glass partition wall installed`,
    'utf-8'
  );

  // ZTI-004: DRA Training Certificate
  fs.writeFileSync(
    path.join(auditDir, 'DRA_Certificate_John_Smith.txt'),
    `NATIONAL BANKING & FINANCIAL EDUCATION TRUST
CERTIFICATE OF COMPLETION - DRA TRAINED
This is to certify that:
Agent / Employee: John Smith
Training Name: Debt Recovery Agent (DRA) Certification
Certificate Number: DRA-2026-99481
Status: PASSED
Issue Date: 2026-06-12
Expiry Date: 2029-06-12`,
    'utf-8'
  );

  // ZTI-005: Police Verification (Applied)
  fs.writeFileSync(
    path.join(auditDir, 'Police_Verification_Acknowledgement.txt'),
    `STATE POLICE DEPARTMENT - CHARACTER & BACKGROUND CLEARANCE
Application Type: Police Verification Report (PV)
Employee: John Smith
Status: APPLIED
Acknowledgement Slip Number: PV-ACK-2026-8812
Date of Application: 10/07/2026
Note: Official background report verification pending police department dispatch.`,
    'utf-8'
  );

  // ZTI-008: USB Access Policy vs Implementation Screenshot
  fs.writeFileSync(
    path.join(auditDir, 'USB_and_Cloud_Storage_Restriction_Policy.txt'),
    `POLICY DOCUMENT: ENDPOINT SECURITY & REMOVABLE MEDIA RESTRICTION
Document Title: USB and Cloud Storage Restriction Policy v2.1
Status: POLICY DOCUMENT FOUND
Mandate: All USB storage devices, cloud drives, and local printers must be disabled across phone lending workstations.`,
    'utf-8'
  );

  fs.writeFileSync(
    path.join(auditDir, 'USB_Restriction_GPO_Active_Dump.txt'),
    `ACTIVE GPO AUDIT LOG & CONFIGURATION EXPORT
GPO Name: SEC-DISABLE-REMOVABLE-MEDIA
Policy State: ENABLED
System Dump Screenshot Export: USB Storage blocked via registry key StorPort=4.
Implementation Proof: Active GPO configuration export attached.`,
    'utf-8'
  );

  // GCI-004: Mandatory Refresher Training Attendance Sheet
  fs.writeFileSync(
    path.join(auditDir, 'Refresher_Training_Attendance_Sheet.csv'),
    `Training_Name,Date,Trainer,Participant_Name,Attendance_Status,Completion_Status
Q2 Code of Conduct Refresher,2026-05-20,Sarah Jenkins,John Smith,PRESENT,COMPLETED
Q2 Code of Conduct Refresher,2026-05-20,Sarah Jenkins,Jane Doe,PRESENT,COMPLETED
Q2 Code of Conduct Refresher,2026-05-20,Sarah Jenkins,Robert Chen,PRESENT,COMPLETED`,
    'utf-8'
  );

  // GCI-008: Windows Patch Report
  fs.writeFileSync(
    path.join(auditDir, 'Windows_OS_Patch_Compliance_Report.csv'),
    `Device_ID,OS_Version,Build_Number,Patch_Level,Status
SYS-PL-001,Windows 11 Enterprise,22631.3880,Current 2026-07 Patch,COMPLIANT
SYS-PL-002,Windows 11 Enterprise,22631.3880,Current 2026-07 Patch,COMPLIANT`,
    'utf-8'
  );

  // IPM-001: PF & ESIC Certificate
  fs.writeFileSync(
    path.join(auditDir, 'PF_ESIC_Registration_Certificates.txt'),
    `EMPLOYEES PROVIDENT FUND ORGANISATION (EPFO)
PF Registration Certificate No: MH/BAN/0099123/000
EMPLOYEES STATE INSURANCE CORPORATION (ESIC)
ESIC Code: 31000998820001001
Status: ACTIVE & VALID`,
    'utf-8'
  );

  // IPM-003: Rent Lease & Shops Certificate
  fs.writeFileSync(
    path.join(auditDir, 'Commercial_Rent_Lease_Agreement.txt'),
    `COMMERCIAL LEASE AGREEMENT FOR AGENCY PREMISES
Lessor: Metro Real Estate Trust
Lessee: Zenith Telecalling & Collection Services Pvt Ltd
Premises: Suite 400, Commercial Plaza, Sector 18
Term: 01/01/2024 to 31/12/2028`,
    'utf-8'
  );

  fs.writeFileSync(
    path.join(auditDir, 'Shops_and_Establishment_Certificate.txt'),
    `MUNICIPAL CORPORATION - SHOPS AND ESTABLISHMENT CERTIFICATE
Registration No: SHOP-MUM-2024-88310
Establishment Name: Zenith Telecalling & Collection Services
Valid Until: 31/12/2027`,
    'utf-8'
  );

  // IPM-004: Commercial Insurance Policy
  fs.writeFileSync(
    path.join(auditDir, 'Commercial_General_Liability_Insurance.txt'),
    `COMMERCIAL GENERAL LIABILITY INSURANCE POLICY
Insurer: National Insurance Corp
Policy Number: CGL-2026-559012
Insured Organization: Zenith Telecalling & Collection Services
Coverage Amount: $1,000,000 USD
Start Date: 2026-01-01
Expiry Date: 2027-12-31
Status: ACTIVE`,
    'utf-8'
  );

  // IPM-006: CCTV Config and 90 Days Retention
  fs.writeFileSync(
    path.join(auditDir, 'CCTV_System_Inventory_and_90Day_Retention.txt'),
    `CCTV SURVEILLANCE SYSTEM & STORAGE CONFIGURATION
CCTV Installed: 12 High-Definition Cameras covering entrances, lending bays, and server room.
Retention Settings: NVR Storage Array configured for 90 days retention minimum (Auto-archive enabled).
Storage Configuration: 16TB RAID-5 Storage Array active.`,
    'utf-8'
  );

  // IPM-007: Fire Extinguisher Inspection
  fs.writeFileSync(
    path.join(auditDir, 'Fire_Extinguisher_Inspection_Tag.txt'),
    `FIRE SAFETY & EXTINGUISHER MAINTENANCE LOG
Equipment: ABC Dry Chemical Powder Extinguisher 5KG
Location: Main Bay & Server Room
Status: AVAILABLE and FUNCTIONAL
Last Inspection Date: 15/06/2026
Expiry Date / Next Refill: 15/06/2027`,
    'utf-8'
  );

  // IPM-008: Fire Drill Report
  fs.writeFileSync(
    path.join(auditDir, 'Annual_Fire_Drill_Report.txt'),
    `FIRE DRILL REPORT & EVACUATION RECORD
Agency: Zenith Telecalling
Drill Date: 2026-03-15
Drill Type: Full Facility Fire Evacuation Drill
Participants: 45 Employees
Trainer / Safety Marshal: Fire Safety Services Corp
Outcome: Successful evacuation in 2 minutes 30 seconds.`,
    'utf-8'
  );

  // IPM-009: Power / Internet / Antivirus
  fs.writeFileSync(
    path.join(auditDir, 'Infrastructure_Backup_and_Antivirus_Config.txt'),
    `INFRASTRUCTURE RESILIENCE & BACKUP AUDIT LOG
Power Backup: 30KVA Online UPS + Diesel Generator Auto-Switching Active
Internet Backup: Secondary Dual Fiber ISP Line (Primary: ISP-A, Backup: ISP-B)
Antivirus: CrowdStrike Falcon EDR Endpoint Protection active across 100% systems`,
    'utf-8'
  );

  // IPM-010: BCP Document
  fs.writeFileSync(
    path.join(auditDir, 'Business_Continuity_Plan_BCP.txt'),
    `BUSINESS CONTINUITY & DISASTER RECOVERY PLAN (BCP)
Document Title: Enterprise BCP & BCM Manual v3.0
Effective Date: 2026-01-10
Review Date: 2026-12-15
Approving Authority: Managing Director & Chief Compliance Officer`,
    'utf-8'
  );

  // IPM-011: Escalation Matrix
  fs.writeFileSync(
    path.join(auditDir, 'Collection_Agency_Escalation_Matrix.txt'),
    `COLLECTION AGENCY ESCALATION MATRIX & HIERARCHY
Level 1 Escalation: Team Lead - Sarah Jenkins (+1-555-0112)
Level 2 Escalation: Operations Manager - Robert Chen (+1-555-0182)
Level 3 Escalation: Head of Compliance - David Vance (+1-555-0177)`,
    'utf-8'
  );

  // 1. CSV Payroll file
  const payrollCsvPath = path.join(baseDir, 'finance', 'Q3_Payroll_2026.csv');
  const csvContent = `Employee_ID,Name,Email,Phone,Bank_Account,IFSC_Code,Monthly_Salary,Tax_PAN
EMP-101,John Doe,john.doe@acme-corp.internal,+1-555-0198,987654321012,HDFC0001234,$12500,ABCDE1234F
EMP-102,Jane Smith,jane.smith@acme-corp.internal,+1-555-0144,876543210987,ICIC0005678,$14200,XYZPS9876K
EMP-103,Robert Chen,robert.chen@acme-corp.internal,+1-555-0182,567890123456,SBIN0008910,$18000,LMNOP5544Q
EMP-104,Sarah Jenkins,sarah.jenkins@acme-corp.internal,+1-555-0112,345678901234,UTIB0002233,$11500,PQRST1122M
`;
  fs.writeFileSync(payrollCsvPath, csvContent, 'utf-8');

  // 2. TXT AWS & Secret Keys file
  const devKeysPath = path.join(baseDir, 'dev-keys', 'aws_credentials.txt');
  const txtContent = `# Production AWS Credentials - DO NOT SHARE
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

# Stripe Live Integration Token
STRIPE_SECRET_KEY=sk_live_51NxEXAMPLE99882211
JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
DATABASE_URL=postgres://admin:Password123!@10.0.1.45:5432/prod_db
`;
  fs.writeFileSync(devKeysPath, txtContent, 'utf-8');

  // 3. TXT Network Topology & Security
  const secPath = path.join(baseDir, 'security', 'internal_network_map.txt');
  const secContent = `================================================
INTERNAL NETWORK ARCHITECTURE & CREDENTIAL SUMMARY
================================================
Primary Gateway: 10.0.0.1
VPN Endpoint: 172.16.10.5
DB Server Cluster: 10.0.1.45, 10.0.1.46
Staging Server: 192.168.1.100

SSH Access Config:
Host prod-app-01
  HostName 10.0.2.15
  User ubuntu
  IdentityFile ~/.ssh/id_rsa_prod

Internal Admin Portal Password: password = AdminPassword2026!
`;
  fs.writeFileSync(secPath, secContent, 'utf-8');

  // 4. Public Handbook (Safe TXT file)
  const pubPath = path.join(baseDir, 'public', 'company_handbook.txt');
  const pubContent = `Welcome to FileSentinel Technologies!
Our mission is to safeguard enterprise data privacy through local-first static inspection.

Office Hours: 9:00 AM - 5:00 PM
Support Email: support@filesentinel.example.com
General Phone: +1-800-555-0199

Code of Conduct:
1. Treat all customer data with extreme care.
2. Never export sensitive unencrypted files to unauthorized public locations.
3. Report any potential data leaks immediately to the Security Operations Center.
`;
  fs.writeFileSync(pubPath, pubContent, 'utf-8');

  // 5. REAL XLSX BINARY FILE
  const xlsxPath = path.join(baseDir, 'finance', 'Tax_Audit_Worksheet.xlsx');
  try {
    const wb = XLSX.utils.book_new();

    const summaryData = [
      ['Metric', 'Amount', 'Notes'],
      ['Total Income', 1250000, 'Reported Gross'],
      ['Tax Paid', 250000, 'Verified Paid'],
      ['Net Profit', '', 'Formula calculated net']
    ];
    const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
    wsSummary['B4'] = { t: 'n', f: 'B2-B3', v: 1000000 };
    wsSummary['C4'] = { t: 's', v: 'Link', l: { Target: 'http://external-partner-sync.org/link.xlsx' } };

    XLSX.utils.book_append_sheet(wb, wsSummary, 'Summary');

    const execData = [
      ['Role', 'Salary', 'Bank Account', 'PAN'],
      ['CEO', 450000, '123456789012', 'AAAAA1111A'],
      ['CFO', 380000, '987654321098', 'BBBBB2222B']
    ];
    const wsExec = XLSX.utils.aoa_to_sheet(execData);
    XLSX.utils.book_append_sheet(wb, wsExec, 'Executive_Salaries');

    wb.Workbook = {
      Sheets: [
        { name: 'Summary', Hidden: 0 },
        { name: 'Executive_Salaries', Hidden: 1 }
      ]
    };

    const xlsxBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    fs.writeFileSync(xlsxPath, xlsxBuffer);
  } catch (err) {
    console.error('Error generating sample XLSX:', err);
  }

  // 6. REAL DOCX BINARY ZIP FILE
  const docxPath = path.join(baseDir, 'hr', 'Employee_Directory.docx');
  try {
    const zip = new JSZip();
    zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`);

    zip.file('_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`);

    zip.file('docProps/core.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>HR Admin Team</dc:creator>
  <dc:title>Employee Directory &amp; HR Review</dc:title>
  <cp:revision>3</cp:revision>
</cp:coreProperties>`);

    zip.file('word/document.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>EMPLOYEE DIRECTORY &amp; HR COMPLIANCE REVIEW</w:t></w:r></w:p>
    <w:p><w:r><w:t>Director Alice Miller: alice.miller@acme-corp.internal - Phone: +1-555-0190 - Credit Card: 4532 0112 8899 4433</w:t></w:r></w:p>
    <w:p><w:r><w:t>VP David Vance: david.vance@acme-corp.internal - Phone: +1-555-0177 - PAN: GHIJK5678L</w:t></w:r></w:p>
  </w:body>
</w:document>`);

    zip.file('word/_rels/document.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdExt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://untrusted-external-portal.com/data-exfil" TargetMode="External"/>
</Relationships>`);

    zip.file('word/embeddings/oleObject1.bin', 'OLE_EMBEDDED_DATA_SIMULATION');

    const buf = await zip.generateAsync({ type: 'nodebuffer' });
    fs.writeFileSync(docxPath, buf);
  } catch (err) {
    console.error('Error generating sample DOCX:', err);
  }

  // 7. REAL PPTX BINARY ZIP FILE
  const pptxPath = path.join(baseDir, 'reports', 'Board_Presentation.pptx');
  try {
    const zip = new JSZip();
    zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
</Types>`);

    zip.file('_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>`);

    zip.file('ppt/presentation.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>
    <p:sldId id="256" r:id="rId1"/>
    <p:sldId id="257" r:id="rId2"/>
    <p:sldId id="258" r:id="rId3" show="0"/>
  </p:sldIdLst>
</p:presentation>`);

    zip.file('ppt/slides/slide1.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>PRESENTATION: Q3 BOARD REVIEW</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>`);

    zip.file('ppt/slides/slide2.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody>
    <a:p><a:r><a:t>Server Infrastructure: Host 10.0.4.12</a:t></a:r></a:p>
    <a:p><a:r><a:t>VPN Credentials: user=admin pass=SecretVPNPass2026!</a:t></a:r></a:p>
  </p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>`);

    zip.file('ppt/slides/slide3.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody>
    <a:p><a:r><a:t>Hidden Slide: Pending Legal Settlement Reserve: $5,000,000</a:t></a:r></a:p>
    <a:p><a:r><a:t>Bank IFSC: SBIN0001234</a:t></a:r></a:p>
  </p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>`);

    zip.file('ppt/notesSlides/notesSlide1.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Speaker Note: Emphasize security compliance to the board.</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
</p:notes>`);

    const buf = await zip.generateAsync({ type: 'nodebuffer' });
    fs.writeFileSync(pptxPath, buf);
  } catch (err) {
    console.error('Error generating sample PPTX:', err);
  }

  // 8. REAL PDF BINARY FILE
  const pdfPath = path.join(baseDir, 'reports', 'annual_audit_2026.pdf');
  const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /JS (app.alert('PDF JavaScript Execution Attempt')) /Launch (cmd.exe) >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 300 >>
stream
BT
/F1 12 Tf
100 700 Td
(ANNUAL SECURITY AND FINANCIAL AUDIT REPORT 2026) Tj
0 -20 Td
(CONFIDENTIAL - INTERNAL USE ONLY) Tj
0 -20 Td
(Server DB: postgres://dbuser:DbPass2026@10.0.1.99:5432/finance_db) Tj
0 -20 Td
(API Key: AIzaSyD091283EXAMPLESECRET) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000115 00000 n 
0000000174 00000 n 
0000000263 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
600
%%EOF
`;
  fs.writeFileSync(pdfPath, pdfContent, 'utf-8');

  return [
    payrollCsvPath,
    devKeysPath,
    secPath,
    pubPath,
    docxPath,
    pdfPath,
    xlsxPath,
    pptxPath
  ];
}
