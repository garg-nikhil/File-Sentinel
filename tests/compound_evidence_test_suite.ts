import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { CompoundEvaluator } from '../backend/audit/compoundEvaluator.js';
import { AuditParameter, EvidenceItem, SubControlRequirement } from '../backend/audit/models.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: any) {
  if (condition) {
    console.log(`✅ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`❌ FAIL: ${testName}`, detail ? detail : '');
    failed++;
  }
}

console.log('====================================================');
console.log('REMEDIATION 4: STRICT COMPOUND EVIDENCE TEST SUITE');
console.log('====================================================\n');

const evaluator = new AuditEvaluator();
const matcher = new EvidenceMatcher();
const checklist = INITIAL_AUDIT_CHECKLIST;

const getParam = (id: string): AuditParameter => {
  const p = checklist.find(param => param.id === id);
  if (!p) throw new Error(`Parameter ${id} not found in checklist`);
  return JSON.parse(JSON.stringify(p)); // Deep clone
};

// ----------------------------------------------------
// 1. IPM-003: Rent/Lease Agreement AND Shops Certificate
// ----------------------------------------------------
const ipm003 = getParam('IPM-003');

const leaseEvidence: EvidenceItem = {
  evidence_id: 'E-LEASE-01',
  file_id: 'F1',
  filename: 'Premises_Commercial_Lease_Agreement.pdf',
  path: '/audit/Premises_Commercial_Lease_Agreement.pdf',
  evidence_type: 'LEASE_AGREEMENT',
  relevance: 0.95,
  snippet: 'COMMERCIAL LEASE AGREEMENT entered between Lessor ABC Properties and Lessee Agency Solutions for premises at 4th Floor, Tech Park. Monthly rent of Rs. 85,000 for a term of 3 years.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: {
    is_policy: false,
    is_implementation: false
  }
};

const shopsEvidence: EvidenceItem = {
  evidence_id: 'E-SHOPS-01',
  file_id: 'F2',
  filename: 'Form_C_Shops_Establishment_Certificate.pdf',
  path: '/audit/Form_C_Shops_Establishment_Certificate.pdf',
  evidence_type: 'SHOPS_ESTABLISHMENT_CERTIFICATE',
  relevance: 0.96,
  snippet: 'GOVERNMENT OF KARNATAKA DEPARTMENT OF LABOUR FORM C REGISTRATION CERTIFICATE OF COMMERCIAL ESTABLISHMENT Registration No: SEC-2024-88491 under Shops and Commercial Establishments Act.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: {
    shops_registration_no: 'SEC-2024-88491',
    is_policy: false,
    is_implementation: false
  }
};

const genericSentenceEvidence: EvidenceItem = {
  evidence_id: 'E-GEN-01',
  file_id: 'F3',
  filename: 'Company_Profile.txt',
  path: '/audit/Company_Profile.txt',
  evidence_type: 'UNKNOWN',
  relevance: 0.50,
  snippet: 'The agency rents premises and is registered under shops and establishment.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: false,
  fieldValidation: false,
  extracted_fields: {
    is_policy: true,
    is_implementation: false
  }
};

// Test 1: IPM-003 Lease Only -> REVIEW
const res1 = evaluator.evaluateParameter(ipm003, [leaseEvidence], '2026-08-15');
assert(res1.status === 'REVIEW', 'Test 1: IPM-003 Lease Only returns REVIEW (Partial fulfillment)');
assert(res1.sub_control_statuses?.['RENT_LEASE_AGREEMENT'] === 'PASS', 'Test 1: Lease sub-control is PASS');
assert(res1.sub_control_statuses?.['SHOPS_ESTABLISHMENT_CERTIFICATE'] === 'EVIDENCE_NOT_FOUND', 'Test 1: Shops sub-control is EVIDENCE_NOT_FOUND');

// Test 2: IPM-003 Shops Only -> REVIEW
const res2 = evaluator.evaluateParameter(ipm003, [shopsEvidence], '2026-08-15');
assert(res2.status === 'REVIEW', 'Test 2: IPM-003 Shops Only returns REVIEW (Partial fulfillment)');
assert(res2.sub_control_statuses?.['RENT_LEASE_AGREEMENT'] === 'EVIDENCE_NOT_FOUND', 'Test 2: Lease sub-control is EVIDENCE_NOT_FOUND');
assert(res2.sub_control_statuses?.['SHOPS_ESTABLISHMENT_CERTIFICATE'] === 'PASS', 'Test 2: Shops sub-control is PASS');

// Test 3: IPM-003 Both Lease and Shops -> PASS
const res3 = evaluator.evaluateParameter(ipm003, [leaseEvidence, shopsEvidence], '2026-08-15');
assert(res3.status === 'PASS', 'Test 3: IPM-003 with both Lease and Shops returns PASS');
assert(res3.score_earned > 0, 'Test 3: IPM-003 earned full points on PASS');

// Test 4: IPM-003 Single generic sentence with both keywords -> REVIEW with 0 score (failed validation)
const res4 = evaluator.evaluateParameter(ipm003, [genericSentenceEvidence], '2026-08-15');
assert(res4.status === 'REVIEW' && res4.score_earned === 0, 'Test 4: IPM-003 generic keyword mention fails validation and does NOT pass');

// ----------------------------------------------------
// 2. IPM-001: PF & ESIC OR Principal Employer (OR Logic)
// ----------------------------------------------------
const ipm001 = getParam('IPM-001');

const pfEsicEvidence: EvidenceItem = {
  evidence_id: 'E-PF-01',
  file_id: 'F4',
  filename: 'EPFO_ESIC_Registration_Certificate.pdf',
  path: '/audit/EPFO_ESIC_Registration_Certificate.pdf',
  evidence_type: 'PF_ESIC_CERTIFICATE',
  relevance: 0.95,
  snippet: 'EMPLOYEES PROVIDENT FUND ORGANISATION Establishment Code: KN/BNG/0049281/000 and ESIC Code: 31000492810001001 Certificate of Registration.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: {
    epfo_code: 'KN/BNG/0049281/000',
    esic_code: '31000492810001001'
  }
};

const peEvidence: EvidenceItem = {
  evidence_id: 'E-PE-01',
  file_id: 'F5',
  filename: 'Principal_Employer_CLRA_Registration.pdf',
  path: '/audit/Principal_Employer_CLRA_Registration.pdf',
  evidence_type: 'PRINCIPAL_EMPLOYER_CERTIFICATE',
  relevance: 0.95,
  snippet: 'FORM I CERTIFICATE OF REGISTRATION OF PRINCIPAL EMPLOYER under Contract Labour (Regulation and Abolition) Act, 1970. Registration No: PE-CLRA-2023-9918.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: {
    principal_employer_reg_no: 'PE-CLRA-2023-9918'
  }
};

const genericPfMention: EvidenceItem = {
  evidence_id: 'E-PF-GEN',
  file_id: 'F6',
  filename: 'HR_Handbook.pdf',
  path: '/audit/HR_Handbook.pdf',
  evidence_type: 'UNKNOWN',
  relevance: 0.45,
  snippet: 'All staff are governed by PF and ESIC statutory guidelines as applicable.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: false,
  fieldValidation: false,
  extracted_fields: { is_policy: true }
};

// Test 5: IPM-001 PF/ESIC Only -> PASS (OR logic)
const res5 = evaluator.evaluateParameter(ipm001, [pfEsicEvidence], '2026-08-15');
assert(res5.status === 'PASS', 'Test 5: IPM-001 with PF/ESIC only returns PASS (OR logic satisfied)');
assert(res5.score_earned > 0, 'Test 5: IPM-001 earned full score on PF/ESIC');

// Test 6: IPM-001 Principal Employer Only -> PASS (OR logic)
const res6 = evaluator.evaluateParameter(ipm001, [peEvidence], '2026-08-15');
assert(res6.status === 'PASS', 'Test 6: IPM-001 with Principal Employer certificate only returns PASS (OR logic satisfied)');

// Test 7: IPM-001 Generic PF mention without certificate/code -> REVIEW (not PASS)
const res7 = evaluator.evaluateParameter(ipm001, [genericPfMention], '2026-08-15');
assert(res7.status === 'REVIEW' && res7.score_earned === 0, 'Test 7: IPM-001 generic mention does NOT pass');

// Test 8: IPM-001 Neither -> EVIDENCE_NOT_FOUND
const res8 = evaluator.evaluateParameter(ipm001, [], '2026-08-15');
assert(res8.status === 'EVIDENCE_NOT_FOUND', 'Test 8: IPM-001 with no evidence returns EVIDENCE_NOT_FOUND');

// ----------------------------------------------------
// 3. IPM-009: Group Controls (Power / Internet / Antivirus)
// ----------------------------------------------------
const ipm009 = getParam('IPM-009');

const powerEvidence: EvidenceItem = {
  evidence_id: 'E-PWR-01',
  file_id: 'F7',
  filename: 'UPS_DG_Maintenance_Log.pdf',
  path: '/audit/UPS_DG_Maintenance_Log.pdf',
  evidence_type: 'POWER_BACKUP_LOG',
  relevance: 0.95,
  snippet: 'Uninterruptible Power Supply (UPS) 20 kVA maintenance log and DG Set generator load test conducted with 4 hours battery runtime verified.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_implementation: true }
};

const internetEvidence: EvidenceItem = {
  evidence_id: 'E-NET-01',
  file_id: 'F8',
  filename: 'Secondary_ISP_Failover_Config.pdf',
  path: '/audit/Secondary_ISP_Failover_Config.pdf',
  evidence_type: 'INTERNET_BACKUP_CONFIG',
  relevance: 0.95,
  snippet: 'Dual-WAN Gateway Router Failover Configuration with Secondary Leased Line ISP circuit Airtel 100Mbps active backup.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_implementation: true }
};

const antivirusEvidence: EvidenceItem = {
  evidence_id: 'E-AV-01',
  file_id: 'F9',
  filename: 'Endpoint_Protection_Defender_Report.pdf',
  path: '/audit/Endpoint_Protection_Defender_Report.pdf',
  evidence_type: 'ANTIVIRUS_CONSOLE_REPORT',
  relevance: 0.95,
  snippet: 'Microsoft Defender Endpoint Protection agent deployment console export. 100% active agents with latest virus definitions update.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_implementation: true }
};

// Test 9: IPM-009 Power Backup Only -> REVIEW with 1/3 score
const res9 = evaluator.evaluateParameter(ipm009, [powerEvidence], '2026-08-15');
assert(res9.status === 'REVIEW', 'Test 9: IPM-009 Power Backup only returns REVIEW');
assert(res9.sub_control_statuses?.['POWER_BACKUP'] === 'PASS', 'Test 9: Power Backup is PASS');
assert(res9.sub_control_statuses?.['INTERNET_BACKUP'] === 'EVIDENCE_NOT_FOUND', 'Test 9: Internet Backup is EVIDENCE_NOT_FOUND');
assert(res9.sub_control_statuses?.['ANTIVIRUS'] === 'EVIDENCE_NOT_FOUND', 'Test 9: Antivirus is EVIDENCE_NOT_FOUND');

// Test 10: IPM-009 Power + Internet -> REVIEW with 2/3 score
const res10 = evaluator.evaluateParameter(ipm009, [powerEvidence, internetEvidence], '2026-08-15');
assert(res10.status === 'REVIEW', 'Test 10: IPM-009 Power + Internet returns REVIEW');
assert(res10.score_earned > res9.score_earned, 'Test 10: 2/3 controls earns more score than 1/3');

// Test 11: IPM-009 All 3 satisfied -> PASS with full score
const res11 = evaluator.evaluateParameter(ipm009, [powerEvidence, internetEvidence, antivirusEvidence], '2026-08-15');
assert(res11.status === 'PASS', 'Test 11: IPM-009 with all 3 controls returns PASS');
assert(res11.score_earned === res11.max_score, 'Test 11: Full score earned on all 3 controls');

// Test 12: Evidence Isolation: 3 copies of Power Backup do NOT satisfy Internet or Antivirus
const powerCopy1 = { ...powerEvidence, evidence_id: 'E-PWR-COPY1', filename: 'UPS_Log_1.pdf' };
const powerCopy2 = { ...powerEvidence, evidence_id: 'E-PWR-COPY2', filename: 'UPS_Log_2.pdf' };
const res12 = evaluator.evaluateParameter(ipm009, [powerEvidence, powerCopy1, powerCopy2], '2026-08-15');
assert(res12.status === 'REVIEW', 'Test 12: Multiple power backup documents do NOT fulfill Internet or Antivirus');
assert(res12.sub_control_statuses?.['INTERNET_BACKUP'] === 'EVIDENCE_NOT_FOUND', 'Test 12: Internet Backup remains EVIDENCE_NOT_FOUND');
assert(res12.sub_control_statuses?.['ANTIVIRUS'] === 'EVIDENCE_NOT_FOUND', 'Test 12: Antivirus remains EVIDENCE_NOT_FOUND');

// ----------------------------------------------------
// 4. IPM-006: CCTV Installed AND 90 Days Retention
// ----------------------------------------------------
const ipm006 = getParam('IPM-006');

const cctvInstallEvidence: EvidenceItem = {
  evidence_id: 'E-CCTV-01',
  file_id: 'F10',
  filename: 'CCTV_Hardware_Inventory_Layout.pdf',
  path: '/audit/CCTV_Hardware_Inventory_Layout.pdf',
  evidence_type: 'CCTV_INSTALLATION_RECORD',
  relevance: 0.94,
  snippet: 'CCTV Surveillance Camera Installation Commissioning Report. 16 Channels Hikvision Dome Cameras covering entry, floor bay, and server room.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_implementation: true }
};

const cctvRetentionEvidence: EvidenceItem = {
  evidence_id: 'E-CCTV-RET',
  file_id: 'F11',
  filename: 'NVR_Recording_Retention_Config.pdf',
  path: '/audit/NVR_Recording_Retention_Config.pdf',
  evidence_type: 'CCTV_RETENTION_CONFIGURATION',
  relevance: 0.95,
  snippet: 'NVR Storage Calculation & Retention Settings. 8TB Hard Drive allocated for continuous recording with 90 days retention cycle before overwrite.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_implementation: true }
};

const cctvPolicyOnly: EvidenceItem = {
  evidence_id: 'E-CCTV-POL',
  file_id: 'F12',
  filename: 'Surveillance_Policy.pdf',
  path: '/audit/Surveillance_Policy.pdf',
  evidence_type: 'POLICY_DOCUMENT',
  relevance: 0.50,
  snippet: 'Policy: The agency shall maintain CCTV cameras and recordings shall be retained for 90 days.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: false,
  fieldValidation: false,
  extracted_fields: { is_policy: true, is_implementation: false }
};

// Test 13: IPM-006 Installation Only -> REVIEW
const res13 = evaluator.evaluateParameter(ipm006, [cctvInstallEvidence], '2026-08-15');
assert(res13.status === 'REVIEW', 'Test 13: IPM-006 CCTV Installation only returns REVIEW');
assert(res13.sub_control_statuses?.['CCTV_INSTALLED'] === 'PASS', 'Test 13: CCTV installation sub-control is PASS');
assert(res13.sub_control_statuses?.['CCTV_RETENTION_90_DAYS'] === 'EVIDENCE_NOT_FOUND', 'Test 13: Retention sub-control is EVIDENCE_NOT_FOUND');

// Test 14: IPM-006 Policy Only -> REVIEW (not PASS)
const res14 = evaluator.evaluateParameter(ipm006, [cctvPolicyOnly], '2026-08-15');
assert(res14.status === 'REVIEW' && res14.score_earned === 0, 'Test 14: IPM-006 Policy document alone cannot pass without operational evidence');

// Test 15: IPM-006 Installation + 90 Days Retention -> PASS
const res15 = evaluator.evaluateParameter(ipm006, [cctvInstallEvidence, cctvRetentionEvidence], '2026-08-15');
assert(res15.status === 'PASS', 'Test 15: IPM-006 Installation + Retention configuration returns PASS');

// ----------------------------------------------------
// 5. Evidence Isolation: Fire Drill (IPM-008) vs Fire Extinguisher (IPM-007)
// ----------------------------------------------------
const ipm007 = getParam('IPM-007');

const fireDrillEvidence: EvidenceItem = {
  evidence_id: 'E-DRILL-01',
  file_id: 'F13',
  filename: 'Annual_Fire_Safety_Evacuation_Drill_Report.pdf',
  path: '/audit/Annual_Fire_Safety_Evacuation_Drill_Report.pdf',
  evidence_type: 'FIRE_DRILL_REPORT',
  relevance: 0.95,
  snippet: 'FIRE DRILL EVACUATION REPORT conducted on 2026-03-10 with 45 participants and warden assembly point verification.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { drill_date: '2026-03-10' }
};

const extinguisherEvidence: EvidenceItem = {
  evidence_id: 'E-EXT-01',
  file_id: 'F14',
  filename: 'Fire_Extinguisher_Inspection_Tag.pdf',
  path: '/audit/Fire_Extinguisher_Inspection_Tag.pdf',
  evidence_type: 'FIRE_EXTINGUISHER_INSPECTION',
  relevance: 0.95,
  snippet: 'Fire Extinguisher ABC Powder Cylinder Inspection and Maintenance Log. Pressure gauge green/OK, Serviced date 2026-01-10, Next refill due 2027-01-10.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: {
    issue_date: '2026-01-10',
    expiry_date: '2027-01-10'
  }
};

// Test 16: Fire Drill report provided for Fire Extinguisher -> EVIDENCE_NOT_FOUND / FAIL (Isolation)
const res16 = evaluator.evaluateParameter(ipm007, [fireDrillEvidence], '2026-08-15');
assert(res16.status !== 'PASS', 'Test 16: Fire Drill report does NOT satisfy Fire Extinguisher parameter (Evidence Isolation)');

// Test 17: Valid Fire Extinguisher Inspection -> PASS
const res17 = evaluator.evaluateParameter(ipm007, [extinguisherEvidence], '2026-08-15');
assert(res17.status === 'PASS', 'Test 17: Valid Fire Extinguisher inspection log returns PASS');

// ----------------------------------------------------
// 6. ZTI-008 & ZTI-009 Policy vs Implementation Compound Controls
// ----------------------------------------------------
const zti008 = getParam('ZTI-008');

const usbPolicy: EvidenceItem = {
  evidence_id: 'E-USB-POL',
  file_id: 'F15',
  filename: 'Endpoint_Security_Policy.pdf',
  path: '/audit/Endpoint_Security_Policy.pdf',
  evidence_type: 'ENDPOINT_SECURITY_POLICY',
  relevance: 0.85,
  snippet: 'Approved Information Security Policy: USB removable media storage and unauthorized cloud storage drives are strictly prohibited on all workstations.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_policy: true, is_implementation: false }
};

const usbGpoImpl: EvidenceItem = {
  evidence_id: 'E-USB-GPO',
  file_id: 'F16',
  filename: 'Domain_GPO_USB_Block_Export.pdf',
  path: '/audit/Domain_GPO_USB_Block_Export.pdf',
  evidence_type: 'DLP_GPO_CONFIGURATION_EXPORT',
  relevance: 0.95,
  snippet: 'Group Policy Management Console GPO Export: RemovableStorageDevices/Deny_All_Access = ENABLED. USB Storage class blocked on all endpoint workstations.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_policy: false, is_implementation: true }
};

// Test 18: ZTI-008 Policy Only -> REVIEW (missing Implementation)
const res18 = evaluator.evaluateParameter(zti008, [usbPolicy], '2026-08-15');
assert(res18.status === 'REVIEW', 'Test 18: ZTI-008 Policy only returns REVIEW');

// Test 19: ZTI-008 Policy + GPO Implementation -> PASS
const res19 = evaluator.evaluateParameter(zti008, [usbPolicy, usbGpoImpl], '2026-08-15');
assert(res19.status === 'PASS', 'Test 19: ZTI-008 Policy + GPO Implementation returns PASS');

const zti009 = getParam('ZTI-009');

const webFilterPolicy: EvidenceItem = {
  evidence_id: 'E-WEB-POL',
  file_id: 'F17',
  filename: 'Acceptable_Internet_Usage_Policy.pdf',
  path: '/audit/Acceptable_Internet_Usage_Policy.pdf',
  evidence_type: 'WEB_FILTERING_POLICY',
  relevance: 0.85,
  snippet: 'Acceptable Usage Policy: Social media websites, personal email portals, and messaging apps must be blacklisted across operational networks.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_policy: true, is_implementation: false }
};

const firewallBlacklistImpl: EvidenceItem = {
  evidence_id: 'E-FW-IMPL',
  file_id: 'F18',
  filename: 'Firewall_URL_Blacklist_Rules.pdf',
  path: '/audit/Firewall_URL_Blacklist_Rules.pdf',
  evidence_type: 'FIREWALL_PROXY_CONFIGURATION_EXPORT',
  relevance: 0.95,
  snippet: 'Fortinet FortiGate Firewall URL Filter Profile: Category Social.Media = BLOCK, Category Personal.Email = BLOCK, Telegram/WhatsApp web = DROP.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  fieldValidation: true,
  extracted_fields: { is_policy: false, is_implementation: true }
};

// Test 20: ZTI-009 Policy Only -> REVIEW
const res20 = evaluator.evaluateParameter(zti009, [webFilterPolicy], '2026-08-15');
assert(res20.status === 'REVIEW', 'Test 20: ZTI-009 Policy only returns REVIEW');

// Test 21: ZTI-009 Policy + Firewall Implementation -> PASS
const res21 = evaluator.evaluateParameter(zti009, [webFilterPolicy, firewallBlacklistImpl], '2026-08-15');
assert(res21.status === 'PASS', 'Test 21: ZTI-009 Policy + Firewall Implementation returns PASS');

// ----------------------------------------------------
// 7. Nested Requirement Group Evaluation: (A OR B) AND (C OR D)
// ----------------------------------------------------
const nestedParam: AuditParameter = {
  id: 'CUSTOM-NESTED-01',
  category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
  category_name: 'Custom Nested Control',
  category_weight: 100,
  parameter: 'Nested Operational Resilience',
  severity: 'MEDIUM',
  required_evidence: ['Power/Generator Evidence', 'ISP Connectivity'],
  keywords: ['power', 'generator', 'isp', 'internet'],
  logic: 'AND',
  fatal: false,
  evaluation_rules: ['(Power OR Generator) AND (Primary ISP OR Backup ISP)'],
  enabled: true,
  requirements: [
    {
      id: 'POWER_RESILIENCE_GROUP',
      name: 'Power Resilience',
      description: 'Power Backup or Generator',
      logic: 'OR',
      requirements: [
        {
          id: 'POWER_BACKUP',
          name: 'UPS Power Backup',
          description: 'UPS Backup Log',
          evidence_types: ['POWER_BACKUP_LOG']
        },
        {
          id: 'GENERATOR_BACKUP',
          name: 'DG Generator Set',
          description: 'Generator Log',
          evidence_types: ['GENERATOR_LOG']
        }
      ]
    },
    {
      id: 'NETWORK_RESILIENCE_GROUP',
      name: 'Network Resilience',
      description: 'Primary or Secondary Internet Link',
      logic: 'OR',
      requirements: [
        {
          id: 'INTERNET_BACKUP',
          name: 'Secondary ISP Failover',
          description: 'Secondary ISP config',
          evidence_types: ['INTERNET_BACKUP_CONFIG']
        }
      ]
    }
  ]
};

// Test 22: Nested Logic Evaluation
const res22Partial = evaluator.evaluateParameter(nestedParam, [powerEvidence], '2026-08-15');
assert(res22Partial.status === 'REVIEW', 'Test 22a: Nested (Power OR DG) AND (ISP) returns REVIEW when only Power is provided');

const res22Complete = evaluator.evaluateParameter(nestedParam, [powerEvidence, internetEvidence], '2026-08-15');
assert(res22Complete.status === 'PASS', 'Test 22b: Nested (Power OR DG) AND (ISP) returns PASS when both groups are satisfied');

console.log('\n====================================================');
console.log(`SUMMARY: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
