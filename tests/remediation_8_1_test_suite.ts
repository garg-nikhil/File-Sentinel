import assert from 'node:assert';
import { EvidenceMatcher, calculateEvidencePriority } from '../backend/audit/evidenceMatcher.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { ExtractionResult } from '../backend/extractors/base.js';
import { classifyDocumentDomain, assertEvidenceDomainMatchesControl } from '../backend/audit/evidenceDomain.js';
import { AuditParameter } from '../backend/audit/models.js';

function getParam(id: string): AuditParameter {
  const param = INITIAL_AUDIT_CHECKLIST.find(p => p.id === id);
  assert.ok(param, `Parameter ${id} must exist in checklist`);
  return param;
}

function createExtraction(text: string, warnings: string[] = []): ExtractionResult {
  return {
    text,
    metadata: {},
    links: [],
    embeddedObjects: [],
    structure: {},
    warnings
  };
}

async function runRemediation81Tests() {
  console.log('================================================================');
  console.log('  FileSentinel Remediation 8.1: False-Negative & Prioritization Test Suite');
  console.log('================================================================\n');

  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();
  const auditDate = '2026-08-15';

  // -------------------------------------------------------------
  // TEST 1: 04_dra_valid.docx on ZTI-004
  // -------------------------------------------------------------
  console.log('[TEST 1] 04_dra_valid.docx on ZTI-004 (DRA Certificate)...');
  const draDocText = `Agent Name: John Synthetic
Agent ID: AG-GOLD-001
Employee ID: EMP-GOLD-001
Certificate Number: DRA/2026/8912
Training Status: PASSED
Issue Date: 10/02/2026`;

  const draExtraction = createExtraction(draDocText);
  const draDomain = classifyDocumentDomain('04_dra_valid.docx', draDocText, draExtraction);
  assert.strictEqual(draDomain.primaryDomain, 'DRA_CERTIFICATION', `04_dra_valid.docx must classify as DRA_CERTIFICATION, got ${draDomain.primaryDomain}`);

  const zti004 = getParam('ZTI-004');
  const draEvidence = matcher.matchDocumentToParameter(
    'file-dra-01',
    '04_dra_valid.docx',
    draExtraction,
    zti004
  );

  assert.ok(draEvidence, 'DRA document must match ZTI-004 parameter');
  assert.strictEqual(draEvidence?.validated, true, 'DRA document must be marked as validated');
  assert.strictEqual(draEvidence?.extracted_fields?.certificate_number, 'DRA/2026/8912', 'Certificate number must be extracted');
  assert.strictEqual(draEvidence?.extracted_fields?.person_name, 'John Synthetic', 'Person name must be extracted');

  const draEvalResult = evaluator.evaluateParameter(zti004, [draEvidence!], auditDate);
  assert.strictEqual(draEvalResult.status, 'PASS', `ZTI-004 must PASS with 04_dra_valid.docx, got ${draEvalResult.status}: ${draEvalResult.reason}`);
  assert.strictEqual(draEvalResult.score_earned, 10, 'ZTI-004 score must be 10/10');
  console.log('  ✔ PASS: ZTI-004 validated with 04_dra_valid.docx (Score: 10/10, Cert No: DRA/2026/8912, Agent: John Synthetic).\n');

  // -------------------------------------------------------------
  // TEST 2: 15_usb_implementation.csv + 14_usb_policy.pdf on ZTI-008
  // -------------------------------------------------------------
  console.log('[TEST 2] 15_usb_implementation.csv & 14_usb_policy.pdf on ZTI-008 (Endpoint / USB Restriction)...');
  const usbPolicyText = `Information Security Policy - Removable Media & USB Restriction Policy
Document ID: POL-SEC-USB-01
Approved By: Chief Information Security Officer
Effective Date: 01/01/2025
Scope: All employee laptops, desktops, workstations, and thin clients.
1. Policy Statement:
All USB mass storage devices, flash drives, external HDDs, and removable media are strictly blocked.
Writing or copying organization data to unauthorized external storage is strictly prohibited.`;

  const usbImplText = `Endpoint_ID,Hostname,OS,USB_Storage_Status,Removable_Media_GPO_Status,DLP_Policy_Applied,Last_Applied_Date
EP-001,SYN-WS-001,Windows 11,BLOCKED,ENFORCED,STRICT-BLOCK-ALL,2026-02-10
EP-002,SYN-WS-002,Windows 11,BLOCKED,ENFORCED,STRICT-BLOCK-ALL,2026-02-10
EP-003,SYN-WS-003,Windows 11,BLOCKED,ENFORCED,STRICT-BLOCK-ALL,2026-02-10`;

  const usbPolicyExtraction = createExtraction(usbPolicyText);
  const usbImplExtraction = createExtraction(usbImplText);

  const policyDomain = classifyDocumentDomain('14_usb_policy.pdf', usbPolicyText, usbPolicyExtraction);
  const implDomain = classifyDocumentDomain('15_usb_implementation.csv', usbImplText, usbImplExtraction);

  assert.strictEqual(policyDomain.primaryDomain, 'ENDPOINT_SECURITY_POLICY', `14_usb_policy.pdf must classify as ENDPOINT_SECURITY_POLICY, got ${policyDomain.primaryDomain}`);
  assert.strictEqual(implDomain.primaryDomain, 'ENDPOINT_DATA_RESTRICTION_CONFIG', `15_usb_implementation.csv must classify as ENDPOINT_DATA_RESTRICTION_CONFIG, got ${implDomain.primaryDomain}`);

  const zti008 = getParam('ZTI-008');
  const policyEvidence = matcher.matchDocumentToParameter(
    'file-usb-pol',
    '14_usb_policy.pdf',
    usbPolicyExtraction,
    zti008
  );

  const implEvidence = matcher.matchDocumentToParameter(
    'file-usb-impl',
    '15_usb_implementation.csv',
    usbImplExtraction,
    zti008
  );

  assert.ok(policyEvidence, 'Policy evidence must match ZTI-008');
  assert.ok(implEvidence, 'Implementation evidence must match ZTI-008');

  const usbEvalResult = evaluator.evaluateParameter(zti008, [policyEvidence!, implEvidence!], auditDate);
  assert.strictEqual(usbEvalResult.status, 'PASS', `ZTI-008 must PASS with policy + impl, got ${usbEvalResult.status}: ${usbEvalResult.reason}`);
  assert.strictEqual(usbEvalResult.score_earned, 10, 'ZTI-008 score must be 10/10');
  console.log('  ✔ PASS: ZTI-008 compound sub-controls satisfied (Policy + Technical CSV implementation dump) (Score: 10/10).\n');

  // -------------------------------------------------------------
  // TEST 3: Evidence Prioritization Ranking
  // -------------------------------------------------------------
  console.log('[TEST 3] Evidence Prioritization Rule ranking verification...');
  const genericDocText = `USB device guidelines and general employee workstation manual. Mentions USB usage policy.`;
  const genericDocExtraction = createExtraction(genericDocText);
  const genericEvidence = matcher.matchDocumentToParameter(
    'file-generic',
    'employee_manual.pdf',
    genericDocExtraction,
    zti008
  );

  const implPriorityForConfig = calculateEvidencePriority(implEvidence!, zti008, 'ENDPOINT_DATA_RESTRICTION_CONFIG');
  const policyPriorityForConfig = calculateEvidencePriority(policyEvidence!, zti008, 'ENDPOINT_DATA_RESTRICTION_CONFIG');
  const genericPriority = calculateEvidencePriority(genericEvidence, zti008, 'ENDPOINT_DATA_RESTRICTION_CONFIG');

  const policyPriorityForPolicy = calculateEvidencePriority(policyEvidence!, zti008, 'ENDPOINT_SECURITY_POLICY');
  const implPriorityForPolicy = calculateEvidencePriority(implEvidence!, zti008, 'ENDPOINT_SECURITY_POLICY');

  assert.ok(implPriorityForConfig > genericPriority, `Technical CSV dump priority (${implPriorityForConfig}) must exceed generic manual (${genericPriority})`);
  assert.ok(implPriorityForConfig > policyPriorityForConfig, `For technical config sub-control, implementation priority (${implPriorityForConfig}) must exceed policy (${policyPriorityForConfig})`);
  assert.ok(policyPriorityForPolicy > implPriorityForPolicy, `For policy sub-control, policy priority (${policyPriorityForPolicy}) must exceed implementation (${implPriorityForPolicy})`);
  console.log(`  ✔ PASS: Technical CSV priority (${implPriorityForConfig}) > Policy priority for config (${policyPriorityForConfig}) & Policy priority for policy (${policyPriorityForPolicy}) > Impl for policy (${implPriorityForPolicy}).\n`);

  // -------------------------------------------------------------
  // TEST 4: Anti-Regression - GST isolated from IPM-003
  // -------------------------------------------------------------
  console.log('[TEST 4] Anti-Regression: GST document against IPM-003 (Rent/Lease)...');
  const gstDocText = `Goods and Services Tax Registration Certificate Form GST REG-06 27AABCA1234F1Z5 ABC Services Private Limited`;
  const gstExtraction = createExtraction(gstDocText);
  const ipm003 = getParam('IPM-003');
  const gstMatch = matcher.matchDocumentToParameter(
    'file-gst',
    '01_positive_gst.txt',
    gstExtraction,
    ipm003
  );
  assert.strictEqual(gstMatch, null, 'GST document must NOT match IPM-003');
  console.log('  ✔ PASS: GST document strictly isolated from IPM-003.\n');

  // -------------------------------------------------------------
  // TEST 5: Anti-Regression - CCTV isolated from ZTI-002 and ZTI-009
  // -------------------------------------------------------------
  console.log('[TEST 5] Anti-Regression: CCTV evidence against ZTI-002 & ZTI-009...');
  const cctvImplText = `CCTV Surveillance System Commissioning & Retention Report Hikvision 4MP Dome NVR-7616NI-Q2 16TB 90 days retention`;
  const cctvExtraction = createExtraction(cctvImplText);
  const zti002 = getParam('ZTI-002');
  const zti009 = getParam('ZTI-009');

  const cctvMatchZti002 = matcher.matchDocumentToParameter('file-cctv', '13_cctv_implementation.pptx', cctvExtraction, zti002);
  const cctvMatchZti009 = matcher.matchDocumentToParameter('file-cctv', '13_cctv_implementation.pptx', cctvExtraction, zti009);

  assert.strictEqual(cctvMatchZti002, null, 'CCTV must NOT match ZTI-002 (Biometric Access)');
  assert.strictEqual(cctvMatchZti009, null, 'CCTV must NOT match ZTI-009 (Web/Social Blacklisting)');
  console.log('  ✔ PASS: CCTV evidence strictly isolated from ZTI-002 & ZTI-009.\n');

  // -------------------------------------------------------------
  // TEST 6: Anti-Regression - manifest.csv rejected from all controls
  // -------------------------------------------------------------
  console.log('[TEST 6] Anti-Regression: manifest.csv rejected from audit evidence pipeline...');
  const manifestText = `filename,status,sha256\n01_positive_gst.txt,OK,abc123\n15_usb_implementation.csv,OK,def456`;
  const manifestExtraction = createExtraction(manifestText);
  const manifestDomain = classifyDocumentDomain('manifest.csv', manifestText, manifestExtraction);
  assert.strictEqual(manifestDomain.primaryDomain, 'UNASSIGNED', 'manifest.csv must be UNASSIGNED');
  console.log('  ✔ PASS: manifest.csv rejected from audit evidence pipeline.\n');

  console.log('================================================================');
  console.log('  ALL REMEDIATION 8.1 TESTS PASSED SUCCESSFULLY! ✔');
  console.log('================================================================\n');
}

runRemediation81Tests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Test Failed:', err);
  process.exit(1);
});
