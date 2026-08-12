import fs from 'node:fs';
import path from 'node:path';

export function ensureSampleFilesExist(baseDir: string = './sample-files'): string[] {
  const folders = [
    path.join(baseDir, 'finance'),
    path.join(baseDir, 'dev-keys'),
    path.join(baseDir, 'hr'),
    path.join(baseDir, 'security'),
    path.join(baseDir, 'public'),
    path.join(baseDir, 'reports')
  ];

  for (const f of folders) {
    if (!fs.existsSync(f)) {
      fs.mkdirSync(f, { recursive: true });
    }
  }

  // 1. CSV Payroll file
  const payrollCsvPath = path.join(baseDir, 'finance', 'Q3_Payroll_2026.csv');
  if (!fs.existsSync(payrollCsvPath)) {
    const csvContent = `Employee_ID,Name,Email,Phone,Bank_Account,IFSC_Code,Monthly_Salary,Tax_PAN
EMP-101,John Doe,john.doe@acme-corp.internal,+1-555-0198,987654321012,HDFC0001234,$12500,ABCDE1234F
EMP-102,Jane Smith,jane.smith@acme-corp.internal,+1-555-0144,876543210987,ICIC0005678,$14200,XYZPS9876K
EMP-103,Robert Chen,robert.chen@acme-corp.internal,+1-555-0182,567890123456,SBIN0008910,$18000,LMNOP5544Q
EMP-104,Sarah Jenkins,sarah.jenkins@acme-corp.internal,+1-555-0112,345678901234,UTIB0002233,$11500,PQRST1122M
`;
    fs.writeFileSync(payrollCsvPath, csvContent, 'utf-8');
  }

  // 2. TXT AWS & Secret Keys file
  const devKeysPath = path.join(baseDir, 'dev-keys', 'aws_credentials.txt');
  if (!fs.existsSync(devKeysPath)) {
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
  }

  // 3. TXT Network Topology & Security
  const secPath = path.join(baseDir, 'security', 'internal_network_map.txt');
  if (!fs.existsSync(secPath)) {
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
  }

  // 4. Public Handbook (Safe TXT file)
  const pubPath = path.join(baseDir, 'public', 'company_handbook.txt');
  if (!fs.existsSync(pubPath)) {
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
  }

  // 5. DOCX sample simulation (TXT format readable or standard zip xml structure if needed)
  const docxPath = path.join(baseDir, 'hr', 'Employee_Directory.docx');
  if (!fs.existsSync(docxPath)) {
    // Generate a simple text-based office document structure
    const docxContent = `EMPLOYEE DIRECTORY & HR COMPLIANCE REVIEW
Author: HR Admin Team
Created: 2026-06-15

List of Active Directors:
- Alice Miller (Director of Engineering) - alice.miller@acme-corp.internal - Phone: +1-555-0190 - Credit Card on File: 4532 0112 8899 4433
- David Vance (VP Finance) - david.vance@acme-corp.internal - Phone: +1-555-0177 - PAN: GHIJK5678L

Embedded Object Reference: ole_object_financial_sheet_v1.bin
External Relationship: http://untrusted-external-portal.com/data-exfil
`;
    fs.writeFileSync(docxPath, docxContent, 'utf-8');
  }

  // 6. PDF sample report
  const pdfPath = path.join(baseDir, 'reports', 'annual_audit_2026.pdf');
  if (!fs.existsSync(pdfPath)) {
    const pdfContent = `%PDF-1.4
%âãÏÓ
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
<< /Length 250 >>
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
0000000018 00000 n 
0000000115 00000 n 
0000000174 00000 n 
0000000263 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
570
%%EOF
`;
    fs.writeFileSync(pdfPath, pdfContent, 'utf-8');
  }

  // 7. XLSX Sample
  const xlsxPath = path.join(baseDir, 'finance', 'Tax_Audit_Worksheet.xlsx');
  if (!fs.existsSync(xlsxPath)) {
    const xlsxContent = `Workbook Name: Tax_Audit_Worksheet.xlsx
Sheet 1: Summary (Visible)
Total Income: $1,250,000
Tax Paid: $250,000

Sheet 2: Executive_Salaries (hidden_sheet)
CEO Salary: $450,000 - Bank Account: 123456789012 - PAN: AAAAA1111A
CFO Salary: $380,000 - Bank Account: 987654321098 - PAN: BBBBB2222B

External_Relationship: [http://external-partner-sync.org/link.xlsx]
`;
    fs.writeFileSync(xlsxPath, xlsxContent, 'utf-8');
  }

  // 8. PPTX Sample
  const pptxPath = path.join(baseDir, 'reports', 'Board_Presentation.pptx');
  if (!fs.existsSync(pptxPath)) {
    const pptxContent = `PRESENTATION: Q3 BOARD REVIEW
Slide 1: Executive Overview
Slide 2: Strategic Investments & Server Infrastructure
Server Host: 10.0.4.12
VPN Credentials: user=admin pass=SecretVPNPass2026!
Slide 3 (Hidden Slide): Pending Acquisitions & Legal Settlement Amounts
Legal Reserve Account: $5,000,000
Bank IFSC: SBIN0001234
`;
    fs.writeFileSync(pptxPath, pptxContent, 'utf-8');
  }

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
