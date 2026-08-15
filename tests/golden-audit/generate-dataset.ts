import fs from 'node:fs';
import path from 'node:path';
import * as XLSX from 'xlsx';
import JSZip from 'jszip';

/**
 * Creates a valid PDF binary buffer with exact xref offsets and stream encoding
 */
export function buildPdfBuffer(lines: string[], title: string = 'Document'): Buffer {
  const streamLines = [
    'BT',
    '/F1 12 Tf',
    '50 750 Td',
    ...lines.map((line, idx) => {
      // Escape parentheses in line
      const escaped = line.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
      return idx === 0 ? `(${escaped}) Tj` : `0 -18 Td\n(${escaped}) Tj`;
    }),
    'ET'
  ].join('\n');

  const streamLength = Buffer.byteLength(streamLines, 'utf-8');

  let pdfStr = `%PDF-1.4\n`;
  const offsets: number[] = [];

  // Obj 1: Catalog
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  pdfStr += `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`;

  // Obj 2: Pages
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  pdfStr += `2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n`;

  // Obj 3: Page
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  pdfStr += `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n`;

  // Obj 4: Contents
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  pdfStr += `4 0 obj\n<< /Length ${streamLength} >>\nstream\n${streamLines}\nendstream\nendobj\n`;

  // Obj 5: Font
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  pdfStr += `5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`;

  // Obj 6: Info
  offsets.push(Buffer.byteLength(pdfStr, 'utf-8'));
  const escapedTitle = title.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  pdfStr += `6 0 obj\n<< /Title (${escapedTitle}) /Author (Sentinel Automated System) /CreationDate (D:20260814000000Z) >>\nendobj\n`;

  const startXref = Buffer.byteLength(pdfStr, 'utf-8');
  pdfStr += `xref\n0 7\n0000000000 65535 f \n`;
  for (const off of offsets) {
    const padded = off.toString().padStart(10, '0');
    pdfStr += `${padded} 00000 n \n`;
  }
  pdfStr += `trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R >>\nstartxref\n${startXref}\n%%EOF\n`;

  return Buffer.from(pdfStr, 'utf-8');
}

/**
 * Creates a valid DOCX zip buffer containing paragraphs, tables, and metadata
 */
export async function buildDocxBuffer(
  paragraphs: string[],
  table?: string[][],
  author: string = 'Sentinel Audit Team',
  title: string = 'Audit Document'
): Promise<Buffer> {
  const zip = new JSZip();

  zip.file(
    '[Content_Types].xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`
  );

  zip.file(
    '_rels/.rels',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`
  );

  zip.file(
    'docProps/core.xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>${author}</dc:creator>
  <dc:title>${title}</dc:title>
  <cp:revision>1</cp:revision>
</cp:coreProperties>`
  );

  let bodyXml = paragraphs
    .map(p => `<w:p><w:r><w:t>${escapeXml(p)}</w:t></w:r></w:p>`)
    .join('');

  if (table && table.length > 0) {
    let tableXml = '<w:tbl>';
    for (const row of table) {
      tableXml += '<w:tr>';
      for (const cell of row) {
        tableXml += `<w:tc><w:p><w:r><w:t>${escapeXml(cell)}</w:t></w:r></w:p></w:tc>`;
      }
      tableXml += '</w:tr>';
    }
    tableXml += '</w:tbl>';
    bodyXml += tableXml;
  }

  zip.file(
    'word/document.xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    ${bodyXml}
  </w:body>
</w:document>`
  );

  return zip.generateAsync({ type: 'nodebuffer' });
}

/**
 * Creates a valid XLSX workbook buffer
 */
export function buildXlsxBuffer(sheets: { name: string; data: (string | number)[][] }[]): Buffer {
  const wb = XLSX.utils.book_new();
  for (const s of sheets) {
    const ws = XLSX.utils.aoa_to_sheet(s.data);
    XLSX.utils.book_append_sheet(wb, ws, s.name);
  }
  return XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

/**
 * Creates a valid PPTX zip buffer with slide text, notes, and metadata
 */
export async function buildPptxBuffer(
  slides: { title: string; content: string[]; notes?: string }[],
  author: string = 'Sentinel Presenter',
  presentationTitle: string = 'Audit Presentation'
): Promise<Buffer> {
  const zip = new JSZip();

  let contentTypesOverride = '';
  let presentationSldIds = '';
  let presentationRels = '';

  for (let i = 0; i < slides.length; i++) {
    const sldNum = i + 1;
    const rId = `rId${sldNum}`;
    contentTypesOverride += `<Override PartName="/ppt/slides/slide${sldNum}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>\n`;
    presentationSldIds += `<p:sldId id="${255 + sldNum}" r:id="${rId}"/>\n`;
    presentationRels += `<Relationship Id="${rId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${sldNum}.xml"/>\n`;

    const slide = slides[i];
    let shapesXml = `
      <p:sp>
        <p:txBody>
          <a:p><a:r><a:t>${escapeXml(slide.title)}</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    `;
    for (const paragraph of slide.content) {
      shapesXml += `
        <p:sp>
          <p:txBody>
            <a:p><a:r><a:t>${escapeXml(paragraph)}</a:t></a:r></a:p>
          </p:txBody>
        </p:sp>
      `;
    }

    zip.file(
      `ppt/slides/slide${sldNum}.xml`,
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      ${shapesXml}
    </p:spTree>
  </p:cSld>
</p:sld>`
    );

    if (slide.notes) {
      contentTypesOverride += `<Override PartName="/ppt/notesSlides/notesSlide${sldNum}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>\n`;
      zip.file(
        `ppt/notesSlides/notesSlide${sldNum}.xml`,
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:sp>
        <p:txBody>
          <a:p><a:r><a:t>${escapeXml(slide.notes)}</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:notes>`
      );
    }
  }

  zip.file(
    '[Content_Types].xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  ${contentTypesOverride}
</Types>`
  );

  zip.file(
    '_rels/.rels',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`
  );

  zip.file(
    'docProps/core.xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>${author}</dc:creator>
  <dc:title>${presentationTitle}</dc:title>
  <cp:revision>1</cp:revision>
</cp:coreProperties>`
  );

  zip.file(
    'ppt/presentation.xml',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>
    ${presentationSldIds}
  </p:sldIdLst>
</p:presentation>`
  );

  zip.file(
    'ppt/_rels/presentation.xml.rels',
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  ${presentationRels}
</Relationships>`
  );

  return zip.generateAsync({ type: 'nodebuffer' });
}

function escapeXml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Main generator function that writes all synthetic documents to tests/golden-audit/documents/
 */
export async function generateGoldenDataset(targetDir: string = './tests/golden-audit/documents'): Promise<string[]> {
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const generatedFiles: string[] = [];

  const writeFile = (filename: string, content: Buffer | string) => {
    const fullPath = path.join(targetDir, filename);
    if (typeof content === 'string') {
      fs.writeFileSync(fullPath, content, 'utf-8');
    } else {
      fs.writeFileSync(fullPath, content);
    }
    generatedFiles.push(fullPath);
  };

  // ==========================================
  // 1. PDF FORMAT DOCUMENTS
  // ==========================================

  // PDF 1: ZTI-001 - Valid GST Registration Certificate
  writeFile(
    'GST_Registration_Certificate.pdf',
    buildPdfBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'FORM GST REG-06 - GOVERNMENT OF INDIA',
      'REGISTRATION CERTIFICATE',
      'GSTIN: 27SYNTHETIC0000Z0',
      'Legal Name: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Trade Name: Sentinel Collections',
      'Principal Place of Business: Unit 401, Tech Park Alpha, Mumbai, MH',
      'Date of Liability: 01/04/2024',
      'Date of Validity: From 15/01/2024 To Permanent',
      'Type of Registration: Regular',
      'Agency Identification Board: Board of Directors - John Synthetic, Jane Synthetic'
    ], 'GST Registration Certificate')
  );

  // PDF 2: IPM-004 - Commercial General Liability Insurance Policy
  writeFile(
    'Commercial_General_Liability_Policy.pdf',
    buildPdfBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'COMMERCIAL GENERAL LIABILITY INSURANCE POLICY SCHEDULE',
      'Policy Number: CGL-GOLD-2026-99',
      'Insured Organization: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Insurance Provider: National General Assurance Corporation Ltd',
      'Period of Insurance: From 01/04/2026 To 31/03/2027',
      'Effective Date: 2026-04-01',
      'Expiry Date: 2027-03-31',
      'Coverage Amount / Limit of Liability: INR 50,000,000 Any One Occurrence',
      'Business Description: Telecalling, Debt Collection and Customer Support Services'
    ], 'CGL Insurance Policy')
  );

  // PDF 3: ZTI-004 - DRA Passed Certificate (John Synthetic)
  writeFile(
    'DRA_Certificate_John_Synthetic.pdf',
    buildPdfBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'NATIONAL BANKING & FINANCIAL EDUCATION TRUST (NBFET)',
      'CERTIFICATE OF COMPLETION - DEBT RECOVERY AGENT (DRA)',
      'This is to certify that:',
      'Agent Name: John Synthetic',
      'Agent ID: AG-GOLD-001',
      'Employee ID: EMP-GOLD-001',
      'DRA Certificate Number: DRA-GOLD-2026-001',
      'Training Course: 100 Hours Mandatory DRA Certification Training',
      'Status: PASSED / DRA TRAINED',
      'Issue Date: 2026-05-30',
      'Expiry Date: 2029-05-30'
    ], 'DRA Certificate John Synthetic')
  );

  // PDF 4: CASE 1 (Negative) - Filename Spoofing GST Policy
  writeFile(
    'GST_Policy_Spoofed_Filename.pdf',
    buildPdfBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'INTERNAL POLICY GUIDELINE ON GENERAL TAX PROCEDURES',
      'This internal policy outlines general corporate tax principles.',
      'All departments must adhere to standard accounting practices.',
      'This document contains standard operating text without registration records.'
    ], 'Internal Tax Policy')
  );

  // PDF 5: CASE 3 (Negative) - Expired Insurance Policy Sample
  writeFile(
    'Expired_Insurance_Policy_Sample.pdf',
    buildPdfBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'COMMERCIAL GENERAL LIABILITY INSURANCE POLICY - HISTORICAL EXPIRED',
      'Policy Number: CGL-HIST-2025-01',
      'Insured Organization: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Insurance Provider: Apex Indemnity Mutual',
      'Effective Date: 2025-04-01',
      'Expiry Date: 2026-03-31',
      'Coverage Limit: INR 10,000,000',
      'Status: EXPIRED'
    ], 'Historical Expired Insurance')
  );

  // ==========================================
  // 2. DOCX FORMAT DOCUMENTS
  // ==========================================

  // DOCX 1: IPM-010 - Business Continuity Plan
  writeFile(
    'Business_Continuity_Plan_2026.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'BUSINESS CONTINUITY PLAN (BCP) & DISASTER RECOVERY FRAMEWORK',
      'Document Version: 2.1',
      'Approval Status: APPROVED BY MANAGEMENT',
      'Effective Date: 2026-01-01',
      'Next Review Date: 2026-12-31',
      'Organization: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Scope: Comprehensive recovery procedures for IT systems, telecalling lines, power disruptions, and facility incidents.',
      'Recovery Time Objective (RTO): 2 Hours',
      'Recovery Point Objective (RPO): 15 Minutes'
    ], undefined, 'Sentinel Risk Management', 'Business Continuity Plan 2026')
  );

  // DOCX 2: IPM-002 - HR & Anti-Sexual Harassment POSH Policy
  writeFile(
    'HR_and_Anti_Sexual_Harassment_POSH_Policy.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'HR POLICY & PREVENTION OF SEXUAL HARASSMENT (POSH) POLICY',
      'Document Title: Human Resources & Prevention of Sexual Harassment Policy',
      'Policy Version: 3.0',
      'Effective Date: 2026-01-15',
      'Internal Complaints Committee (ICC) Chairperson: Dr. Sarah Jenkins (External Member)',
      'Committee Members: Jane Synthetic (Presiding Officer), John Synthetic (Member)',
      'Mandate: Zero tolerance for workplace harassment. Formal grievance handling within 90 days.',
      'Employee Code of Conduct handbook approved by Executive Committee.'
    ], undefined, 'HR Governance Committee', 'HR & POSH Policy')
  );

  // DOCX 3: ZTI-008 - Endpoint USB Security Policy
  writeFile(
    'Endpoint_USB_Security_Policy.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'INFORMATION SECURITY POLICY: ENDPOINT SECURITY & USB RESTRICTIONS',
      'Policy Reference: SEC-POL-ENDPOINT-004',
      'Document Title: Endpoint Security Policy & Removable Media Restriction',
      'Policy Version: 2.4',
      'Effective Date: 2026-02-01',
      'Policy Statement: All USB storage devices, external drives, optical media, and unauthorized local printers are strictly prohibited on agency workstations.',
      'Mandate: Hardware ports must be disabled via Active Directory Group Policy Objects (GPO).'
    ], undefined, 'CISO Office', 'Endpoint USB Security Policy')
  );

  // DOCX 4: ZTI-009 - Web Filtering and Social Media Policy
  writeFile(
    'Web_Filtering_Social_Media_Policy.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'ACCEPTABLE USE & WEB FILTERING POLICY',
      'Policy Document: Web Filtering and Social Media Access Restriction Policy',
      'Version: 1.8',
      'Effective Date: 2026-02-15',
      'Mandate: Social media sites, personal webmail (Gmail, Yahoo, Outlook), file sharing drives, and messaging applications are strictly restricted from the operations floor.',
      'Enforcement: DNS sinkholing and firewall proxy URL filtering rules.'
    ], undefined, 'IT Security Committee', 'Web Filtering Policy')
  );

  // DOCX 5: IPM-003 - Commercial Lease Agreement for Premises
  writeFile(
    'Commercial_Lease_Agreement_Premises.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'COMMERCIAL LEASE & RENT AGREEMENT FOR AGENCY PREMISES',
      'This Deed of Lease Agreement is executed on 01/01/2026 by and between:',
      'Lessor / Landlord: Alpha Commercial Properties Real Estate Trust',
      'Lessee / Tenant: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Demised Premises: Unit 401 & 402, 4th Floor, Tech Park Alpha, Mumbai, Maharashtra - 400051',
      'Lease Term: 36 Months commencing from 01/01/2026 to 31/12/2028',
      'Permitted Use: Commercial office space for telecalling and business operations.',
      'Monthly Rent: INR 250,000',
      'Premises Agreement signed and registered.'
    ], undefined, 'Legal Affairs Dept', 'Commercial Lease Agreement')
  );

  // DOCX 6: ZTI-007 - Agent Onboarding & KYC Verification Dossier
  writeFile(
    'Agent_Onboarding_KYC_Verification.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'AGENT ONBOARDING CHECKLIST & KYC AUTHENTICATION RECORD',
      'Agency Name: Sentinel Recovery & Telecalling Services Pvt Ltd',
      'Audit Period: 2026 Annual Review',
      'Onboarding Verification Status: COMPLETED & VERIFIED',
      'The following recovery agents have undergone complete onboarding background checks, KYC document authentication, and manager approval:'
    ], [
      ['Agent Name', 'Agent ID', 'Employee ID', 'KYC Status', 'Approval Date', 'Approving Manager'],
      ['John Synthetic', 'AG-GOLD-001', 'EMP-GOLD-001', 'AUTHENTICATED', '2026-05-15', 'Operations Lead'],
      ['Jane Synthetic', 'AG-GOLD-002', 'EMP-GOLD-002', 'AUTHENTICATED', '2026-05-18', 'Operations Lead']
    ], 'HR Onboarding Operations', 'Agent Onboarding Records')
  );

  // DOCX 7: GCI-006 (Policy Only) - Snipping Tool Restriction Policy
  writeFile(
    'Snipping_Tool_Restriction_Policy.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'INFORMATION SECURITY POLICY: SCREEN CAPTURE RESTRICTION',
      'Policy Title: Snipping Tool Disabled & MS Paint Disabled Security Policy',
      'Version: 1.2',
      'Policy Mandate: Screen capture restricted; Snipping Tool disabled and MS Paint disabled across all telecalling terminal machines via software restriction policy and AppLocker policy.',
      'Governance Status: This document constitutes the formal governance policy document.'
    ], undefined, 'Security Governance', 'Screen Capture Policy')
  );

  // DOCX 8: GCI-002 (Policy Only) - ID Deactivation & Termination Policy
  writeFile(
    'ID_Deactivation_Offboarding_Policy.docx',
    await buildDocxBuffer([
      'SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET',
      'STANDARD OPERATING PROCEDURE: AGENT OFFBOARDING & ID DEACTIVATION',
      'Document Title: Agent Termination Process and ID Deactivation Procedure SOP',
      'Version: 2.0',
      'Policy Mandate: Upon employee exit or termination process, IT and HR must adhere to the ID deactivation offboarding checklist and revoke system access within 2 hours of departure.',
      'Scope: Governance policy and exit process framework.'
    ], undefined, 'HR & IT Operations', 'Deactivation SOP')
  );

  // ==========================================
  // 3. XLSX FORMAT DOCUMENTS
  // ==========================================

  // XLSX 1: GCI-004 - Refresher Training Attendance Sheet
  writeFile(
    'Refresher_Training_Attendance_2026.xlsx',
    buildXlsxBuffer([
      {
        name: 'Attendance_Log',
        data: [
          ['MANDATORY REFRESHER TRAINING ATTENDANCE SHEET & PARTICIPANT LIST', '', '', '', '', '', '', ''],
          ['Refresher Training Module: Annual Code of Conduct & Fair Practices', '', '', '', '', '', '', ''],
          ['Training Log Date: 2026-05-10', 'Trainer: Sarah Jenkins (Master Trainer)', '', '', '', '', '', ''],
          ['Training_Name', 'Date', 'Trainer', 'Participant_Name', 'Agent_ID', 'Employee_ID', 'Attendance_Status', 'Completion_Status'],
          ['Mandatory Refresher Training - Code of Conduct', '2026-05-10', 'Sarah Jenkins (Master Trainer)', 'John Synthetic', 'AG-GOLD-001', 'EMP-GOLD-001', 'PRESENT', 'COMPLETED'],
          ['Mandatory Refresher Training - Code of Conduct', '2026-05-10', 'Sarah Jenkins (Master Trainer)', 'Jane Synthetic', 'AG-GOLD-002', 'EMP-GOLD-002', 'PRESENT', 'COMPLETED'],
          ['Mandatory Refresher Training - Code of Conduct', '2026-05-10', 'Sarah Jenkins (Master Trainer)', 'Alex Synthetic', 'AG-GOLD-003', 'EMP-GOLD-003', 'PRESENT', 'COMPLETED']
        ]
      }
    ])
  );

  // XLSX 2: IPM-006 - CCTV Camera Inventory & Layout
  writeFile(
    'CCTV_Installation_and_Camera_Inventory.xlsx',
    buildXlsxBuffer([
      {
        name: 'Camera_Inventory',
        data: [
          ['Camera_ID', 'Location_Zone', 'Camera_Model', 'IP_Address', 'Status', 'Installation_Date'],
          ['CAM-01', 'Main Entry / Reception', 'Hikvision 4K Dome IP', '192.168.20.101', 'ACTIVE', '2026-01-10'],
          ['CAM-02', 'Bay 4 Phone Lending Floor', 'Hikvision 4K Dome IP', '192.168.20.102', 'ACTIVE', '2026-01-10'],
          ['CAM-03', 'Server Room & UPS Bay', 'Hikvision Varifocal IP', '192.168.20.103', 'ACTIVE', '2026-01-10'],
          ['CAM-04', 'Emergency Exit Corridor', 'Hikvision 4K Dome IP', '192.168.20.104', 'ACTIVE', '2026-01-10'],
          ['CAM-05', 'Operations Floor Bay 1', 'Hikvision 4K Dome IP', '192.168.20.105', 'ACTIVE', '2026-01-10'],
          ['CAM-06', 'Conference Room', 'Hikvision 4K Dome IP', '192.168.20.106', 'ACTIVE', '2026-01-10']
        ]
      },
      {
        name: 'DVR_NVR_System_Config',
        data: [
          ['Attribute', 'Configuration_Value'],
          ['NVR Unit Model', 'Hikvision 32-Channel NVR Pro'],
          ['Installed Storage', '16 TB RAID-5 Array'],
          ['Active Channels', '16 Cameras Connected and Recording']
        ]
      }
    ])
  );

  // XLSX 3: GCI-008 - Windows OS Patch Compliance Report
  writeFile(
    'Windows_OS_Patch_Compliance_Report.xlsx',
    buildXlsxBuffer([
      {
        name: 'Endpoint_Patch_Status',
        data: [
          ['WINDOWS OS PATCH COMPLIANCE REPORT & ENDPOINT INVENTORY', '', '', '', '', '', '', ''],
          ['Windows Update WSUS Report - OS Version & Build Number Compliance Baseline', '', '', '', '', '', '', ''],
          ['Hostname', 'Assigned_User', 'Agent_ID', 'OS Version', 'Build Number', 'Patch Compliance', 'WSUS Report Status', 'Compliance'],
          ['WKSTN-PL-001', 'John Synthetic', 'AG-GOLD-001', 'Windows 11 Enterprise 23H2', '22631.3880', 'KB5040442', 'SYNCED', 'COMPLIANT'],
          ['WKSTN-PL-002', 'Jane Synthetic', 'AG-GOLD-002', 'Windows 11 Enterprise 23H2', '22631.3880', 'KB5040442', 'SYNCED', 'COMPLIANT'],
          ['WKSTN-PL-003', 'Alex Synthetic', 'AG-GOLD-003', 'Windows 11 Enterprise 23H2', '22631.3880', 'KB5040442', 'SYNCED', 'COMPLIANT'],
          ['WKSTN-PL-004', 'Pool Workstation', 'N/A', 'Windows 11 Enterprise 23H2', '22631.3880', 'KB5040442', 'SYNCED', 'COMPLIANT']
        ]
      }
    ])
  );

  // XLSX 4: GCI-007 - Active Directory Password Policy Export
  writeFile(
    'Active_Directory_Password_Policy_Export.xlsx',
    buildXlsxBuffer([
      {
        name: 'Password_Policy_GPO',
        data: [
          ['ACTIVE DIRECTORY PASSWORD POLICY EXPORT & IAM POLICY', '', '', ''],
          ['Active Directory GPO - Complexity Requirements & Password Expiration', '', '', ''],
          ['Policy_Setting', 'Configured_Value', 'Compliance_Baseline', 'Status'],
          ['Minimum Password Length', '12 Characters', '>= 10 Characters', 'COMPLIANT'],
          ['Password Complexity Requirements', 'Enabled (Upper/Lower/Numeric/Special)', 'Enabled', 'COMPLIANT'],
          ['Maximum Password Age / Password Expiration', '90 Days', '<= 90 Days', 'COMPLIANT'],
          ['Minimum Password Age', '1 Day', '>= 1 Day', 'COMPLIANT'],
          ['Password History Enforcement', '24 Passwords Remembered', '>= 12 Passwords', 'COMPLIANT'],
          ['Account Lockout Threshold', '5 Invalid Attempts', '<= 5 Attempts', 'COMPLIANT'],
          ['Lockout Duration', '30 Minutes', '>= 30 Minutes', 'COMPLIANT']
        ]
      }
    ])
  );

  // XLSX 5: GCI-005 - Agency Performance and Target vs Actual Evaluation
  writeFile(
    'Target_vs_Actual_Performance_Evaluation.xlsx',
    buildXlsxBuffer([
      {
        name: 'Performance_Evaluation',
        data: [
          ['AGENCY PERFORMANCE AND EVALUATION REPORT', '', '', '', '', ''],
          ['Target vs Actual Performance Report & Agency Evaluation Matrix', '', '', '', '', ''],
          ['Agency Evaluation Period: 2026 Annual Audit', '', '', '', '', ''],
          ['Metric', 'Target', 'Actual', 'Variance', 'Score_Earned', 'Status'],
          ['Resolution Rate (%)', '85.0%', '89.4%', '+4.4%', '95/100', 'EXCEEDED'],
          ['Customer Quality Score', '90.0%', '93.2%', '+3.2%', '93/100', 'EXCEEDED'],
          ['SLA Adherence', '98.0%', '99.1%', '+1.1%', '99/100', 'EXCEEDED'],
          ['No Dues Certificate (NDC)', '100% Issued', '100% Issued', '0.0%', 'PASS', 'VERIFIED'],
          ['Asset Management Declaration', 'Submitted', 'Verified', 'N/A', 'PASS', 'VERIFIED']
        ]
      }
    ])
  );

  // ==========================================
  // 4. PPTX FORMAT DOCUMENTS
  // ==========================================

  // PPTX 1: IPM-008 - Fire Safety Evacuation Drill Presentation
  writeFile(
    'Fire_Safety_Evacuation_Drill_Report_2026.pptx',
    await buildPptxBuffer([
      {
        title: 'ANNUAL FIRE SAFETY & EVACUATION DRILL REPORT 2026',
        content: [
          'Agency Name: Sentinel Recovery & Telecalling Services Pvt Ltd',
          'Facility: Tech Park Alpha, 4th Floor',
          'Drill Date: 2026-06-01 (Conducted on June 1, 2026)',
          'Conducted By: Safety Officer & Municipal Fire Brigade Liaison'
        ],
        notes: 'Annual mandatory fire drill conducted within the last 12 months.'
      },
      {
        title: 'Drill Execution & Participation Metrics',
        content: [
          'Total Employees Present: 78 Participants',
          'Evacuation Total Time: 2 Minutes 45 Seconds',
          'Assembly Point Clearance: 100% Accounted For',
          'Fire Alarm, Strobe Lights & Hydrant Flow Tested: PASSED',
          'Fire Drill conducted and verified within latest 1 year.'
        ],
        notes: 'Photographic evidence and sign-in sheets stored on internal safety drive.'
      }
    ], 'Safety Operations Team', 'Fire Evacuation Drill 2026')
  );

  // PPTX 2: ZTI-010 - Clean Desk Policy and Workspace Guidelines
  writeFile(
    'Clean_Desk_Policy_and_Audit_Briefing.pptx',
    await buildPptxBuffer([
      {
        title: 'CLEAN DESK & CLEAR SCREEN WORKSPACE GUIDELINES',
        content: [
          'Sentinel Information Security Standard Operating Procedures',
          'Scope: All calling agent pods and management cabins',
          'Requirement: Lock screens upon leaving desk (Win + L). No sensitive borrower notes on paper.'
        ],
        notes: 'Policy deck presented during orientation.'
      },
      {
        title: 'Nightly Inspection Protocol',
        content: [
          'Floor supervisors conduct nightly audits of physical desks.',
          'Note: Physical compliance requires ongoing auditor visual verification.'
        ],
        notes: 'Compliance declarations gathered quarterly.'
      }
    ], 'Security Officer', 'Clean Desk Briefing')
  );

  // ==========================================
  // 5. CSV FORMAT DOCUMENTS
  // ==========================================

  // CSV 1: IPM-009 (Sub-control: Antivirus) - Antivirus Console Export
  writeFile(
    'Endpoint_Antivirus_EDR_Console_Export.csv',
    `# ANTIVIRUS UPDATED & EDR DEFINITIONS CONSOLE AUDIT EXPORT
Hostname,IP_Address,Antivirus_Product,Realtime_Protection,Definitions_Version,Definitions_Date,Status
WKSTN-PL-001,192.168.10.21,Microsoft Defender for Endpoint,ENABLED,1.415.220.0,2026-08-10,HEALTHY_PROTECTED
WKSTN-PL-002,192.168.10.22,Microsoft Defender for Endpoint,ENABLED,1.415.220.0,2026-08-10,HEALTHY_PROTECTED
WKSTN-PL-003,192.168.10.23,Microsoft Defender for Endpoint,ENABLED,1.415.220.0,2026-08-10,HEALTHY_PROTECTED
WKSTN-PL-004,192.168.10.24,Microsoft Defender for Endpoint,ENABLED,1.415.220.0,2026-08-10,HEALTHY_PROTECTED
SRV-AD-001,192.168.10.10,Microsoft Defender for Endpoint,ENABLED,1.415.220.0,2026-08-10,HEALTHY_PROTECTED`
  );

  // CSV 2: ZTI-008 (Sub-control: Implementation) - GPO Removable Storage Export
  writeFile(
    'DLP_GPO_Removable_Storage_Export.csv',
    `# REMOVABLE STORAGE DISABLED - USB STORAGE PROHIBITED ACTIVE DIRECTORY GPO EXPORT
Policy_Name,GPO_GUID,Registry_Key,Value_Name,Configured_Value,State
SEC-GPO-USB-BLOCK,{31B2F340-016D-11D2-945F-00C04FB984F9},HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR,Start,4 (Disabled),APPLIED
SEC-GPO-USB-BLOCK,{31B2F340-016D-11D2-945F-00C04FB984F9},HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices,Deny_All,1 (Blocked),APPLIED
SEC-GPO-USB-BLOCK,{31B2F340-016D-11D2-945F-00C04FB984F9},HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WPD,Deny_Write,1 (Blocked),APPLIED`
  );

  // CSV 3: ZTI-009 (Sub-control: Implementation) - Firewall Proxy Blacklist Export
  writeFile(
    'Firewall_Proxy_Blacklist_Rules_Export.csv',
    `# WEB FILTERING AND SOCIAL MEDIA ACCESS RESTRICTION FIREWALL PROXY BLACKLIST EXPORT
Rule_ID,Category,Target_Domain_Pattern,Action,Firewall_Zone,Log_Status
RULE-FW-0101,Social Media Blacklist,*facebook.com*,DENY,Floor-VLAN-10,ENABLED
RULE-FW-0102,Social Media Blacklist,*instagram.com*,DENY,Floor-VLAN-10,ENABLED
RULE-FW-0103,Social Media Blacklist,*twitter.com*,DENY,Floor-VLAN-10,ENABLED
RULE-FW-0104,Personal Email Blacklist,*mail.google.com*,DENY,Floor-VLAN-10,ENABLED
RULE-FW-0105,Personal Email Blacklist,*mail.yahoo.com*,DENY,Floor-VLAN-10,ENABLED
RULE-FW-0106,Messaging Apps Blacklist,*web.whatsapp.com*,DENY,Floor-VLAN-10,ENABLED`
  );

  // CSV 4: IPM-006 (Sub-control: Retention) - CCTV 90 Days Storage Config Export
  writeFile(
    'CCTV_90_Days_Storage_Retention_Config.csv',
    `# CCTV RECORDING RETENTION CONFIGURATION - 90 DAYS RETENTION LOG & DVR NVR STORAGE
Device_Name,Storage_Pool,Allocated_TB,Recording_Mode,Configured_Retention_Days,Min_Retention_Guarantee,Status
NVR-CORE-01,POOL-RAID5-01,16.0 TB,Continuous 24/7 1080p,90 days retention,90 Days Minimum,COMPLIANT
NVR-CORE-01,POOL-RAID5-02,16.0 TB,Continuous 24/7 1080p,90 days retention,90 Days Minimum,COMPLIANT`
  );

  // CSV 5: IPM-009 (Sub-controls: Power & Internet Backup) - Maintenance Log
  writeFile(
    'Power_and_Internet_Backup_Maintenance_Log.csv',
    `# POWER BACKUP UPS BACKUP DG SET GENERATOR SECONDARY ISP FAILOVER INTERNET MAINTENANCE LOG
Asset_Type,Asset_ID,Vendor_ISP,Capacity_Bandwidth,Last_Inspection_Date,Failover_Test_Result,Status
Power Backup (UPS),UPS-40KVA-01,Schneider Electric APC,40 kVA Online UPS,2026-07-15,4 Hours Battery Backup Test OK,OPERATIONAL
Power Backup (Generator),DG-SET-125KVA,Cummins Diesel Power,125 kVA Auto-Start DG,2026-07-20,Auto Mains Failure (AMF) Test OK,OPERATIONAL
Primary Internet Leased Line,ISP-LINK-01,Tata Tele Business Services,100 Mbps 1:1 Leased Line,2026-08-01,Primary Link Up,ACTIVE
Internet Backup (Secondary ISP),ISP-LINK-02,Airtel Enterprise Broadband,100 Mbps Dual-WAN Failover,2026-08-01,Failover Test 0 Packet Loss,ACTIVE_STANDBY`
  );

  // CSV 6: IPM-005 - Visitor Entry Register CSV
  writeFile(
    'Visitor_Entry_Register_2026.csv',
    `# VISITOR REGISTER & VISITOR ENTRY LOGBOOK - ACTIVE VISITOR LOG
Entry_ID,Date,Visitor_Name,Company_Represented,Person_To_Meet,Badge_Issued,Time_In,Time_Out,Purpose
VIS-2026-0801,2026-08-01,Robert Taylor,Fire Safety Inspection Bureau,Safety Officer,VIS-01,10:15 AM,11:45 AM,Annual Equipment Review
VIS-2026-0803,2026-08-03,Sunil Sharma,Schneider Electric UPS AMC,IT Systems Lead,VIS-02,02:30 PM,04:00 PM,Quarterly Battery Maintenance
VIS-2026-0808,2026-08-08,Pooja Mehta,Telecom Line Engineer,Network Admin,VIS-03,11:00 AM,12:15 PM,Fiber Link Speed Verification`
  );

  // ==========================================
  // 6. TXT FORMAT DOCUMENTS
  // ==========================================

  // TXT 1: IPM-011 - Escalation Matrix Hierarchy
  writeFile(
    'Escalation_Matrix_Hierarchy.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
CUSTOMER GRIEVANCE & OPERATIONAL ESCALATION MATRIX
Organization: Sentinel Recovery & Telecalling Services Pvt Ltd
Active Period: 2026 Operations

LEVEL 1 - TEAM LEAD / FLOOR SUPERVISOR
Contact Role: Floor Support Lead
Email: escalation-l1@sentinel-recovery.synthetic
Response SLA: Within 4 Hours

LEVEL 2 - OPERATIONS MANAGER
Contact Role: Operations Manager
Email: escalation-l2@sentinel-recovery.synthetic
Response SLA: Within 8 Hours

LEVEL 3 - HEAD OF COMPLIANCE & LEGAL
Contact Role: Chief Compliance Officer
Email: compliance-head@sentinel-recovery.synthetic
Response SLA: Within 24 Hours

LEVEL 4 - PRINCIPAL NODAL OFFICER / EXECUTIVE COMMITTEE
Contact Role: Principal Nodal Officer
Email: nodalofficer@sentinel-recovery.synthetic
Response SLA: Within 48 Hours`
  );

  // TXT 2: ZTI-005 - Police Verification Certificate (John Synthetic)
  writeFile(
    'Police_Verification_Certificate_John_Synthetic.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
GOVERNMENT POLICE DEPARTMENT - CHARACTER & BACKGROUND CLEARANCE CERTIFICATE
Verification Report No: PCC-GOLD-2026-101
This is to certify that Police Verification has been conducted for:
Employee / Agent Name: John Synthetic
Agent ID: AG-GOLD-001
Employee ID: EMP-GOLD-001
Address: Flat 204, Green Heights, Mumbai, Maharashtra
Status: VERIFIED / POLICE CLEARANCE CERTIFICATE ISSUED
Result: NO ADVERSE OR CRIMINAL RECORD FOUND
Issue Date: 2026-05-20
Expiry Date: 2027-05-20
Authorized Signatory: Deputy Commissioner of Police`
  );

  // TXT 3: ZTI-005 - Police Verification Acknowledgement Receipt (Jane Synthetic)
  writeFile(
    'Police_Verification_Receipt_Jane_Synthetic.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
POLICE DEPARTMENT CITIZEN SERVICES PORTAL
ACKNOWLEDGEMENT RECEIPT - POLICE VERIFICATION FOR EMPLOYMENT
Application Reference Number: PV-ACK-GOLD-2026-202
Applicant Name: Jane Synthetic
Agent ID: AG-GOLD-002
Employee ID: EMP-GOLD-002
Application Type: Police Verification Certificate (Character Verification)
Status: APPLIED / APPLICATION UNDER PROCESS
Date of Application: 2026-07-10
Note: Proof of Police Verification application submitted by agency.`
  );

  // TXT 4: GCI-001 - Agency ID Card & Field Endorsement Register
  writeFile(
    'Agency_ID_Card_Issue_Register.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
AGENCY IDENTIFICATION CARD & FIELD ENDORSEMENT REGISTER
Issuer: Sentinel Recovery & Telecalling Services Pvt Ltd

CARD ISSUE RECORD:
1. Agent Name: John Synthetic
   Agent ID: AG-GOLD-001
   Employee ID: EMP-GOLD-001
   Designation: Senior Recovery Officer
   ID Card Number: ID-GOLD-001
   Field Endorsement Card Number: END-GOLD-001
   Status: ACTIVE / VALID

2. Agent Name: Jane Synthetic
   Agent ID: AG-GOLD-002
   Employee ID: EMP-GOLD-002
   Designation: Telecalling Associate
   ID Card Number: ID-GOLD-002
   Field Endorsement Card Number: END-GOLD-002
   Status: ACTIVE / VALID`
  );

  // TXT 5: IPM-003 (Sub-control) - Shops and Establishment Certificate
  writeFile(
    'Shops_and_Establishment_Certificate.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
FORM C - GOVERNMENT OF MAHARASHTRA
THE MAHARASHTRA SHOPS AND ESTABLISHMENTS ACT
REGISTRATION CERTIFICATE OF COMMERCIAL ESTABLISHMENT

Registration Certificate Number: SEC-MH-MUM-2026-8812
Name of the Establishment: Sentinel Recovery & Telecalling Services Pvt Ltd
Name of the Employer: John Synthetic (Managing Director)
Address: Unit 401 & 402, Tech Park Alpha, Mumbai, Maharashtra - 400051
Category: Commercial Establishment
Date of Registration: 10/01/2024
Renewed Up To: 31/12/2028
Status: VALID AND ACTIVE`
  );

  // TXT 6: IPM-001 - Principal Employer Registration Certificate
  writeFile(
    'Principal_Employer_CLRA_Registration.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
FORM I - CONTRACT LABOUR (REGULATION AND ABOLITION) ACT
GOVERNMENT OF INDIA - MINISTRY OF LABOUR & EMPLOYMENT
CERTIFICATE OF REGISTRATION OF PRINCIPAL EMPLOYER

Certificate Registration No: PE-CLRA-2026-4412
Principal Employer: Sentinel Recovery & Telecalling Services Pvt Ltd
Establishment Address: Tech Park Alpha, Mumbai - 400051
Maximum Number of Contract / Telecalling Labour Employed: 150
Date of Issue: 2024-02-15
Status: REGISTERED AND COMPLIANT`
  );

  // TXT 7: IPM-007 - Fire Extinguisher Inspection Certificate & Tag Log
  writeFile(
    'Fire_Extinguisher_Inspection_Log.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
FIRE SAFETY EQUIPMENT & FIRE EXTINGUISHER INSPECTION LOG
Facility: Tech Park Alpha, 4th Floor

EXTINGUISHER AUDIT RECORDS:
1. Cylinder Tag: FE-ABC-01 (Location: Bay 4 Entrance)
   Type: ABC Dry Chemical Powder (6 KG)
   Pressure Gauge Status: GREEN / NORMAL OPERATING PRESSURE
   Physical Condition: Serviceable, Pin and Seal Intact, Available on Wall Mount
   Last Refill Date: 2026-05-15
   Next Refill Due Date: 2027-05-15
   Inspection Result: FUNCTIONAL & NOT EXPIRED

2. Cylinder Tag: FE-CO2-02 (Location: Server Room)
   Type: CO2 Carbon Dioxide (4.5 KG)
   Pressure Gauge Status: OK / SERVICEABLE
   Last Refill Date: 2026-05-15
   Next Refill Due Date: 2027-05-15
   Inspection Result: FUNCTIONAL & NOT EXPIRED`
  );

  // TXT 8: CASE 2 (Negative) - Generic PF & ESIC Keyword Only Text
  writeFile(
    'Generic_PF_ESIC_Policy_Keyword_Only.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
GENERAL STATEMENT ON EMPLOYEE STATUTORY BENEFITS
PF and ESIC compliance is mandatory for all personnel.
All staff members must adhere to labor department statutes.`
  );

  // TXT 9: ZTI-002 - Access Control Biometric Log
  writeFile(
    'Biometric_Access_Control_Config.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
AGENCY ACCESS CONTROL & BIOMETRIC SYSTEM CONFIGURATION
System: BioEntry W2 Fingerprint Reader & RFID Card Reader Log System
IP Address: 192.168.10.15
MAC Address: 00:1A:2B:3C:4D:5E
Terminal Config: Controller ID DAC-01 Door Access Controller Active
Daily Access Log:
2026-08-14 08:30:15 - Badge ID: AG-GOLD-001 - John Synthetic - PUNCH IN - Access Granted
2026-08-14 08:35:22 - Badge ID: AG-GOLD-002 - Jane Synthetic - PUNCH IN - Access Granted`
  );

  // TXT 10: ZTI-003 - Dedicated Workspace Allocation
  writeFile(
    'Phone_Lending_Dedicated_Workspace.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
PHONE LENDING BUSINESS WORKSPACE ALLOCATION DECREE
Dedicated Bay: Bay 4 - Segregated Phone Lending Unit
System Allocation: Laptops SYS-PL-001 through SYS-PL-050
Physical Segregation: Keycard locked glass partition wall installed for Phone Lending business`
  );

  // TXT 11: CASE 4 (Conflict Scenario) - Conflicting Police Verification (Jane Synthetic with John's Agent ID)
  writeFile(
    'Conflicting_Police_Verification_Jane_Synthetic.txt',
    `SYNTHETIC TEST DATA - FILESENTINEL GOLDEN DATASET
POLICE DEPARTMENT CHARACTER VERIFICATION RECORD (CONFLICT TEST)
Verification Report No: PCC-CONFLICT-TEST-001
Employee Name: Jane Synthetic
Agent ID: AG-GOLD-001
Employee ID: EMP-GOLD-002
Address: Flat 501, Horizon Tower, Mumbai, Maharashtra
Status: VERIFIED / POLICE CLEARANCE CERTIFICATE
Date: 2026-05-25`
  );

  return generatedFiles;
}
