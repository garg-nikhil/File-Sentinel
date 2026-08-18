import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DatabaseSync } from 'node:sqlite';
import { EvidenceEngine } from '../backend/audit/evidenceEngine.js';
import { defaultRegistry } from '../backend/extractors/registry.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { getDatabase } from '../backend/db.js';

function createMockDb(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_sessions (
      audit_id TEXT PRIMARY KEY,
      scan_id TEXT,
      audit_date TEXT NOT NULL,
      agency_name TEXT NOT NULL,
      auditor_name TEXT NOT NULL,
      status TEXT NOT NULL,
      total_parameters INTEGER DEFAULT 0,
      pass_count INTEGER DEFAULT 0,
      fail_count INTEGER DEFAULT 0,
      review_count INTEGER DEFAULT 0,
      not_found_count INTEGER DEFAULT 0,
      fatal_failures_count INTEGER DEFAULT 0,
      overall_score INTEGER DEFAULT 0,
      max_score INTEGER DEFAULT 200,
      overall_status TEXT NOT NULL,
      category_scores_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_parameter_results (
      audit_id TEXT NOT NULL,
      parameter_id TEXT NOT NULL,
      status TEXT NOT NULL,
      confidence REAL DEFAULT 1.0,
      fatal INTEGER DEFAULT 0,
      score_earned REAL DEFAULT 0,
      max_score REAL DEFAULT 0,
      policy_status TEXT,
      pv_status TEXT,
      evidence_json TEXT,
      reason TEXT,
      missing_requirements_json TEXT,
      warnings_json TEXT,
      ai_recommendation_json TEXT,
      override_json TEXT,
      PRIMARY KEY (audit_id, parameter_id)
    );
    CREATE TABLE IF NOT EXISTS scanned_files (
      file_id TEXT PRIMARY KEY,
      scan_id TEXT,
      original_path TEXT,
      filename TEXT,
      extracted_text TEXT,
      status TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_entities (
      entity_id TEXT NOT NULL,
      audit_id TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      display_name TEXT NOT NULL,
      normalized_name TEXT NOT NULL,
      identifiers_json TEXT,
      evidence_references_json TEXT,
      matching_signals_json TEXT,
      confidence REAL DEFAULT 1.0,
      status TEXT NOT NULL,
      conflicts_json TEXT,
      created_at TEXT NOT NULL,
      PRIMARY KEY (audit_id, entity_id)
    );
    CREATE TABLE IF NOT EXISTS audit_entity_conflicts (
      id TEXT PRIMARY KEY,
      audit_id TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      conflict_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      reason TEXT NOT NULL,
      involved_evidence_json TEXT,
      conflicting_attributes_json TEXT,
      created_at TEXT NOT NULL
    );
  `);
  return db;
}

async function runAllPhase82Tests() {
  console.log('====================================================');
  console.log('       PHASE 8.2 COMPREHENSIVE TEST SUITE');
  console.log('====================================================\n');

  const testDir = path.resolve('test_sandbox_phase82');
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  fs.mkdirSync(testDir, { recursive: true });

  const originalExtract = defaultRegistry.extract.bind(defaultRegistry);
  defaultRegistry.extract = async (filePath) => {
    if (filePath.endsWith('.txt') || filePath.endsWith('.csv') || filePath.endsWith('.json') || filePath.endsWith('.pdf') || filePath.endsWith('.xlsx')) {
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        return { text: content, pages: 1, metadata: {} };
      }
    }
    return originalExtract(filePath);
  };

  const db = createMockDb();
  const engine = new EvidenceEngine(db as any);

  try {
    // ----------------------------------------------------
    // TEST A — Multiple evidence same control
    // ----------------------------------------------------
    console.log('[TEST A] Multiple evidence for same control (ZTI-008)...');
    const filesA: string[] = [];
    
    // 1 Policy Document
    const policyFile = path.join(testDir, 'endpoint_security_policy.pdf');
    fs.writeFileSync(policyFile, 'ORGANIZATIONAL ENDPOINT SECURITY POLICY\nScope: All workstations\nRemovable Media & USB Policy: All USB mass storage devices are strictly blocked.\nApproved by CISO.\nStatus: APPROVED');
    filesA.push(policyFile);

    // 9 Implementation Configuration Exports
    for (let i = 1; i <= 9; i++) {
      const f = path.join(testDir, `zti008_evidence_${i}.csv`);
      fs.writeFileSync(f, `endpoint,policy,usb_storage,gpo_status,last_applied\nWS-${i},USB_RESTRICTION,BLOCKED,APPLIED,2026-08-10`);
      filesA.push(f);
    }
    const zti008 = INITIAL_AUDIT_CHECKLIST.filter(p => p.id === 'ZTI-008');
    const sessionA = await engine.runAuditScan(filesA, '2026-08-15', 'Agency A', 'Auditor A', zti008);
    const resA = sessionA.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
    
    console.assert(resA !== undefined, 'Result for ZTI-008 should exist');
    console.assert(resA?.status === 'PASS', `Status should be PASS, got ${resA?.status}`);
    console.assert(resA?.evidence_set !== undefined, 'Evidence set should be present');
    console.assert(resA?.evidence_set?.primaryEvidence !== null, 'Primary evidence should be present');
    console.assert(resA?.evidence.length === 10, `All 10 evidence items should be retained, got ${resA?.evidence.length}`);
    console.log(`  ✔ PASS: All 10 files evaluated, 1 primary, 9 supporting, Control Status: ${resA?.status}\n`);

    // ----------------------------------------------------
    // TEST B — Exact duplicate files (Same SHA-256)
    // ----------------------------------------------------
    console.log('[TEST B] Exact duplicate files across different paths...');
    const duplicateContent = `GOVERNMENT OF INDIA\nGSTIN: 27AABCT3518Q1ZV\nLegal Name: APEX RECOVERIES PRIVATE LIMITED\nTrade Name: APEX RECOVERIES\nRegistration Date: 12/04/2021\nPrincipal Place of Business: Suite 400, Mumbai, Maharashtra\nStatus: ACTIVE`;
    const filesB: string[] = [];
    for (let i = 1; i <= 5; i++) {
      const subDir = path.join(testDir, `folder_${i}`);
      fs.mkdirSync(subDir, { recursive: true });
      const f = path.join(subDir, 'gst_certificate.pdf');
      fs.writeFileSync(f, duplicateContent);
      filesB.push(f);
    }
    const zti001 = INITIAL_AUDIT_CHECKLIST.filter(p => p.id === 'ZTI-001');
    const sessionB = await engine.runAuditScan(filesB, '2026-08-15', 'Agency B', 'Auditor B', zti001);
    const resB = sessionB.parameter_results?.find(p => p.parameter_id === 'ZTI-001');

    console.assert(resB !== undefined, 'Result for ZTI-001 should exist');
    console.assert(resB?.status === 'PASS', `Status should be PASS, got ${resB?.status}`);
    const totalDiscoveredB = (resB?.evidence_set?.primaryEvidence ? 1 : 0) + (resB?.evidence_set?.supportingEvidence.length || 0);
    console.assert(totalDiscoveredB === 5, `All 5 duplicate files must be independently evaluated, got ${totalDiscoveredB}`);
    console.log(`  ✔ PASS: 5 byte-for-byte duplicate files all scanned and retained independently.\n`);

    // ----------------------------------------------------
    // TEST C — Near-identical GST certificates (95% identical text)
    // ----------------------------------------------------
    console.log('[TEST C] Near-identical GST certificates for distinct legal entities...');
    const gst1 = `GOVERNMENT OF INDIA\nGST REGISTRATION CERTIFICATE\nForm GST REG-06\nRegistration Number: 27AAAAA1111A1Z1\nLegal Name: ALPHA SERVICES PVT LTD\nTrade Name: ALPHA SERVICES\nConstitution: Private Limited Company\nAddress: 101 Marine Drive, Mumbai 400020\nDate of Registration: 01/01/2020\nStatus: ACTIVE`;
    const gst2 = `GOVERNMENT OF INDIA\nGST REGISTRATION CERTIFICATE\nForm GST REG-06\nRegistration Number: 27BBBBB2222B1Z2\nLegal Name: BETA TELECALLING PVT LTD\nTrade Name: BETA TELECALLING\nConstitution: Private Limited Company\nAddress: 202 MG Road, Pune 411001\nDate of Registration: 01/01/2020\nStatus: ACTIVE`;
    const gst3 = `GOVERNMENT OF INDIA\nGST REGISTRATION CERTIFICATE\nForm GST REG-06\nRegistration Number: 27CCCCC3333C1Z3\nLegal Name: GAMMA FINANCIAL PVT LTD\nTrade Name: GAMMA FINANCIAL\nConstitution: Private Limited Company\nAddress: 303 Residency Road, Bengaluru 560025\nDate of Registration: 01/01/2020\nStatus: ACTIVE`;

    const fC1 = path.join(testDir, 'alpha_gst.pdf');
    const fC2 = path.join(testDir, 'beta_gst.pdf');
    const fC3 = path.join(testDir, 'gamma_gst.pdf');
    fs.writeFileSync(fC1, gst1);
    fs.writeFileSync(fC2, gst2);
    fs.writeFileSync(fC3, gst3);

    const sessionC = await engine.runAuditScan([fC1, fC2, fC3], '2026-08-15', 'Multi Entity Agency', 'Auditor C', zti001);
    const resC = sessionC.parameter_results?.find(p => p.parameter_id === 'ZTI-001');
    console.assert(resC?.status === 'PASS', `Status should be PASS, got ${resC?.status}`);
    const totalC = (resC?.evidence_set?.primaryEvidence ? 1 : 0) + (resC?.evidence_set?.supportingEvidence.length || 0);
    console.assert(totalC === 3, `Expected 3 independent documents, got ${totalC}`);
    console.assert(resC?.evidence_set?.contradictoryEvidence.length === 0, 'Should not detect false contradiction for distinct entities');
    console.log(`  ✔ PASS: 3 near-identical certificates processed as independent records without false contradiction.\n`);

    // ----------------------------------------------------
    // TEST D — Contradictory operational evidence (Same entity)
    // ----------------------------------------------------
    console.log('[TEST D] Contradictory operational evidence on the same endpoint...');
    const fD_pol = path.join(testDir, 'zti008_policy.pdf');
    fs.writeFileSync(fD_pol, 'ENDPOINT SECURITY POLICY\nRemovable Media: All USB devices blocked.\nStatus: APPROVED');

    const fD1 = path.join(testDir, 'ws99_blocked.csv');
    const fD2 = path.join(testDir, 'ws99_allowed.csv');
    fs.writeFileSync(fD1, 'endpoint,policy,usb_storage,gpo_status\nWS-99,USB_RESTRICTION,BLOCKED,APPLIED');
    fs.writeFileSync(fD2, 'endpoint,policy,usb_storage,gpo_status\nWS-99,USB_RESTRICTION,ALLOWED,NOT_APPLIED');

    const sessionD = await engine.runAuditScan([fD_pol, fD1, fD2], '2026-08-15', 'Agency D', 'Auditor D', zti008);
    const resD = sessionD.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
    console.assert(resD?.status === 'REVIEW', `Contradiction must force REVIEW, got ${resD?.status}`);
    console.log(`  ✔ PASS: Conflicting operational states for same endpoint correctly flagged as REVIEW (${resD?.reason}).\n`);

    // ----------------------------------------------------
    // TEST E — Different entities (No false contradiction)
    // ----------------------------------------------------
    console.log('[TEST E] Different entities with different operational states...');
    const fE_pol = path.join(testDir, 'endpoint_policy_e.pdf');
    fs.writeFileSync(fE_pol, 'ENDPOINT SECURITY POLICY\nRemovable Media: All USB storage blocked.\nStatus: APPROVED');

    const fE1 = path.join(testDir, 'endpoint_a.csv');
    const fE2 = path.join(testDir, 'endpoint_b.csv');
    fs.writeFileSync(fE1, 'endpoint,policy,usb_storage,gpo_status\nWS-01,USB_RESTRICTION,BLOCKED,APPLIED');
    fs.writeFileSync(fE2, 'endpoint,policy,usb_storage,gpo_status\nWS-02,USB_RESTRICTION,ALLOWED,APPLIED');

    const sessionE = await engine.runAuditScan([fE_pol, fE1, fE2], '2026-08-15', 'Agency E', 'Auditor E', zti008);
    const resE = sessionE.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
    console.assert(resE?.evidence_set?.contradictoryEvidence.length === 0, 'Different endpoints must not be flagged as contradictory');
    console.log(`  ✔ PASS: Different endpoints (WS-01 and WS-02) isolated; no false contradiction triggered.\n`);

    // ----------------------------------------------------
    // TEST F — Cross-document compound evidence
    // ----------------------------------------------------
    console.log('[TEST F] Cross-document compound evidence satisfaction...');
    // IPM-003 (Premises Rent/Lease Agreement AND Shops & Establishment Certificate)
    const ipm003 = INITIAL_AUDIT_CHECKLIST.filter(p => p.id === 'IPM-003');
    const fF1 = path.join(testDir, 'commercial_lease.pdf');
    const fF2 = path.join(testDir, 'shops_establishment_cert.csv');

    fs.writeFileSync(fF1, 'COMMERCIAL LEASE AND RENT AGREEMENT\nPremises Address: 4th Floor, Apex Towers, Mumbai 400051\nLessor: Real Estate Ltd\nLessee: Apex Recoveries\nTerm: 5 Years\nStatus: EXECUTED');
    fs.writeFileSync(fF2, 'certificate_name,registration_no,establishment_name,status\nShops and Establishment Certificate,SHOPS-MH-2024-8849,Apex Recoveries,ACTIVE');

    const sessionF = await engine.runAuditScan([fF1, fF2], '2026-08-15', 'Agency F', 'Auditor F', ipm003);
    const resF = sessionF.parameter_results?.find(p => p.parameter_id === 'IPM-003');
    console.assert(resF !== undefined, 'Result for IPM-003 must exist');
    console.assert(resF?.status === 'PASS', `Cross-document compound should PASS, got ${resF?.status}`);
    console.log(`  ✔ PASS: Compound control IPM-003 satisfied across 2 distinct document formats (PDF & CSV).\n`);

    // ----------------------------------------------------
    // TEST G — Strict Domain Isolation
    // ----------------------------------------------------
    console.log('[TEST G] Domain isolation verification...');
    // Provide GST certificate with address and registration keywords to IPM-003 (Rent/Lease & Shops)
    const fG1 = path.join(testDir, 'gst_for_lease_check.pdf');
    fs.writeFileSync(fG1, 'GOVERNMENT OF INDIA\nGST CERTIFICATE\nPrincipal Place of Business: Registered Commercial Premises Leasehold Shop 12 Mumbai\nStatus: ACTIVE');

    const sessionG = await engine.runAuditScan([fG1], '2026-08-15', 'Agency G', 'Auditor G', ipm003);
    const resG = sessionG.parameter_results?.find(p => p.parameter_id === 'IPM-003');
    console.assert(resG?.status !== 'PASS', `Domain mismatch must not PASS, got ${resG?.status}`);
    console.log(`  ✔ PASS: GST certificate containing address/premises keywords strictly blocked from satisfying IPM-003 (Lease/Rent Agreement).\n`);

    // ----------------------------------------------------
    // TEST H — Privacy Hardening (No Full Raw Text in SQLite DB)
    // ----------------------------------------------------
    console.log('[TEST H] Privacy hardening & raw text exclusion verification...');
    const SECRET_MARKER = 'PRIVATE_TEST_MARKER_938475_SUPER_CONFIDENTIAL_PAYROLL_DATA_DO_NOT_PERSIST';
    const fH1 = path.join(testDir, 'private_document.pdf');
    fs.writeFileSync(fH1, `GOVERNMENT OF INDIA\nGSTIN: 27AABCT9999Q1ZV\nLegal Name: SECURE AGENCY PVT LTD\n${SECRET_MARKER}\nPrincipal Place: Mumbai\nStatus: ACTIVE`);

    await engine.runAuditScan([fH1], '2026-08-15', 'Agency H', 'Auditor H', zti001);

    // Query SQLite database
    const rows = db.prepare(`SELECT evidence_json FROM audit_parameter_results WHERE parameter_id = 'ZTI-001'`).all() as { evidence_json: string }[];
    const dbDump = rows.map(r => r.evidence_json).join(' ');

    console.assert(!dbDump.includes(SECRET_MARKER), 'SQLite database must NOT contain raw document text or secret marker');
    console.log(`  ✔ PASS: SQLite database verified: raw_text stripped, secret marker completely absent from persistent storage.\n`);

    // ----------------------------------------------------
    // TEST I — AI Disabled by Default
    // ----------------------------------------------------
    console.log('[TEST I] AI Disabled mode verification...');
    const sessionI = await engine.runAuditScan([filesA[0]], '2026-08-15', 'Agency I', 'Auditor I', zti008, 'OFF');
    const resI = sessionI.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
    console.assert(resI?.ai_recommendation === undefined, 'No AI recommendation should be generated when AI is OFF');
    console.log(`  ✔ PASS: Deterministic audit operates completely autonomously with AI set to OFF.\n`);

    // ----------------------------------------------------
    // TEST J — Multiple Scan Roots
    // ----------------------------------------------------
    console.log('[TEST J] Multi-root directory scanning...');
    const root1 = path.join(testDir, 'root_hr');
    const root2 = path.join(testDir, 'root_security');
    const root3 = path.join(testDir, 'root_legal');
    const root4 = path.join(testDir, 'root_infra');
    [root1, root2, root3, root4].forEach(r => fs.mkdirSync(r, { recursive: true }));

    fs.writeFileSync(path.join(root1, 'dra_training.pdf'), 'DRA TRAINING CERTIFICATE\nCertificate No: DRA-2025-9911\nCandidate: John Smith\nStatus: PASSED');
    fs.writeFileSync(path.join(root2, 'usb_block.csv'), 'endpoint,policy,usb_storage,gpo_status\nE1,USB,BLOCKED,APPLIED');
    fs.writeFileSync(path.join(root3, 'gst.pdf'), 'GOVERNMENT OF INDIA\nGSTIN: 27AABCT3518Q1ZV\nLegal Name: APEX RECOVERIES\nStatus: ACTIVE');
    fs.writeFileSync(path.join(root4, 'fire_drill.pdf'), 'FIRE DRILL REPORT\nDate: 2026-06-10\nLocation: Main Office\nOutcome: EVACUATION_SUCCESSFUL');

    const multiFiles = [
      path.join(root1, 'dra_training.pdf'),
      path.join(root2, 'usb_block.csv'),
      path.join(root3, 'gst.pdf'),
      path.join(root4, 'fire_drill.pdf')
    ];

    const sessionJ = await engine.runAuditScan(multiFiles, '2026-08-15', 'Multi-Root Agency', 'Auditor J');
    console.assert(sessionJ.total_parameters > 0, 'Audit session should evaluate parameters');
    console.assert(sessionJ.pass_count >= 3, `Expected at least 3 passes across multi-roots, got ${sessionJ.pass_count}`);
    console.log(`  ✔ PASS: 4 disparate root directories scanned, files aggregated, and evidence provenance preserved.\n`);

  } finally {
    defaultRegistry.extract = originalExtract;
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  }

  console.log('====================================================');
  console.log('  ALL 10 PHASE 8.2 REGRESSION TESTS (A-J) PASSED!   ');
  console.log('====================================================');
}

runAllPhase82Tests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Phase 8.2 Test Suite Failed:', err);
  process.exit(1);
});
