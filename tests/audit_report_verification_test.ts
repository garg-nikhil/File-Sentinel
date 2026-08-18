import { getDatabase } from '../backend/db.js';
import { VerifiableAuditReportService } from '../backend/audit/verifiableReportService.js';
import { AuditSession } from '../backend/audit/models.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import crypto from 'node:crypto';

async function runVerifiableReportTestSuite() {
  console.log('========================================================================');
  console.log('  COMMERCIALIZATION PHASE 9: Verifiable Audit Reports Test Suite       ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const verifiableReportService = new VerifiableAuditReportService(db);
  const now = new Date().toISOString();

  // Setup mock orgs and users
  const orgA = 'org-audit-alpha';
  const orgB = 'org-audit-bravo';
  const userA = 'usr-auditor-alpha';
  const userB = 'usr-auditor-bravo';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Alpha Vendor Services', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Bravo Regulatory Group', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userA, orgA, 'alpha_auditor', hashPassword('AuditPass123!'), 'AUDITOR', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userB, orgB, 'bravo_auditor', hashPassword('AuditPass123!'), 'AUDITOR', now);

  // Setup express test app
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  const mockSession: AuditSession = {
    audit_id: 'AUDIT-8A91C2',
    scan_id: 'FS-SCAN-VND001',
    audit_date: '2026-08-16',
    agency_name: 'Apex Telecalling & Collection Services Pvt Ltd',
    auditor_name: 'Lead Regulatory Auditor',
    status: 'COMPLETED',
    total_parameters: 17,
    pass_count: 14,
    fail_count: 2,
    review_count: 1,
    not_found_count: 0,
    fatal_failures_count: 0,
    overall_score: 88,
    max_score: 100,
    overall_status: 'COMPLIANT',
    category_scores: {
      'Information Security': { earned: 25, max: 25, status: 'PASS' }
    },
    parameter_results: [
      {
        parameter_id: 'IS-01',
        parameter: {
          id: 'IS-01',
          category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
          category_name: 'Information Security',
          category_weight: 1.0,
          severity: 'HIGH',
          parameter: 'Information Security Policy Document',
          fatal: false,
          required_evidence: ['Information Security Policy'],
          keywords: ['security', 'policy'],
          logic: 'SINGLE',
          evaluation_rules: [],
          enabled: true
        },
        status: 'PASS',
        confidence: 1.0,
        fatal: false,
        score_earned: 5,
        max_score: 5,
        evidence: [{ file_id: 'f-1', filename: 'InfoSec_Policy_2026.pdf', confidence: 1.0, sourceType: 'DOCUMENT_EVIDENCE', sourceDomain: 'ENDPOINT_SECURITY_POLICY' } as any],
        reason: 'Valid policy detected',
        missing_requirements: [],
        warnings: []
      }
    ],
    created_at: '2026-08-16T10:00:00Z',
    updated_at: '2026-08-16T10:05:00Z'
  };

  // Test 1: Deterministic Hashing
  console.log('Test 1: Deterministic report canonicalization and cryptographic hashing...');
  const canonicalA = verifiableReportService.buildCanonicalReport({
    scan_id: 'FS-SCAN-VND001',
    organization_id: orgA,
    session: mockSession
  });
  const canonicalB = verifiableReportService.buildCanonicalReport({
    scan_id: 'FS-SCAN-VND001',
    organization_id: orgA,
    session: mockSession
  });
  const hashA = verifiableReportService.computeReportHash(canonicalA);
  const hashB = verifiableReportService.computeReportHash(canonicalB);
  assert.strictEqual(hashA.length, 64, 'SHA-256 hash must be exactly 64 hex characters');
  assert.strictEqual(hashA, hashB, 'Identical canonical reports must produce identical hashes');
  console.log(`  ✓ Canonical SHA-256 Hash is deterministic: ${hashA}`);

  // Test 2: Hash Sensitivity (Change detection)
  console.log('Test 2: Modifying audit scores alters the cryptographic hash...');
  const modifiedSession = { ...mockSession, overall_score: 89 };
  const canonicalModified = verifiableReportService.buildCanonicalReport({
    scan_id: 'FS-SCAN-VND001',
    organization_id: orgA,
    session: modifiedSession
  });
  const hashModified = verifiableReportService.computeReportHash(canonicalModified);
  assert.notStrictEqual(hashA, hashModified, 'Modified report must produce different hash');
  console.log(`  ✓ Hash changed on modification: ${hashModified}`);

  // Test 3: Report Registration via Service
  console.log('Test 3: Registering a verifiable audit report...');
  const registered = verifiableReportService.registerReport({
    scan_id: 'FS-SCAN-VND001',
    organization_id: orgA,
    session: mockSession
  });
  assert.ok(registered.report_id.startsWith('FS-RPT-'), 'Report ID must start with FS-RPT-');
  assert.strictEqual(registered.status, 'VALID');
  assert.strictEqual(registered.report_hash, hashA);
  console.log(`  ✓ Registered report: ${registered.report_id} with status ${registered.status}`);

  // Test 4: Verification of authentic report (VALID)
  console.log('Test 4: Verifying authentic registered report...');
  const verifyRes = verifiableReportService.verifyReport(registered.report_id);
  assert.strictEqual(verifyRes.status, 'VALID');
  assert.strictEqual(verifyRes.verified, true);
  assert.strictEqual(verifyRes.hash_matched, true);
  assert.strictEqual(verifyRes.report_hash, registered.report_hash);
  assert.strictEqual(verifyRes.metrics?.overall_score, 88);
  console.log(`  ✓ Verification succeeded: Status ${verifyRes.status}`);

  // Test 5: Forged or non-existent report ID
  console.log('Test 5: Verifying non-existent report returns INVALID...');
  const forgedRes = verifiableReportService.verifyReport('FS-RPT-FORGED-FAKE-001');
  assert.strictEqual(forgedRes.status, 'INVALID');
  assert.strictEqual(forgedRes.verified, false);
  console.log(`  ✓ Forged report correctly returned INVALID: ${forgedRes.message}`);

  // Test 6: Tampered canonical payload detection
  console.log('Test 6: Tampered canonical payload detected during verification...');
  const regTamper = verifiableReportService.registerReport({
    scan_id: 'FS-SCAN-TAMPER001',
    organization_id: orgA,
    session: mockSession
  });
  // Simulate attacker updating stored canonical JSON in SQLite
  const storedRow = db.prepare('SELECT canonical_payload_json FROM audit_reports WHERE report_id = ?').get(regTamper.report_id) as any;
  const tamperedPayload = JSON.parse(storedRow.canonical_payload_json);
  tamperedPayload.overall_score = 99; // Attacker changed score to 99
  db.prepare('UPDATE audit_reports SET canonical_payload_json = ? WHERE report_id = ?').run(
    JSON.stringify(tamperedPayload),
    regTamper.report_id
  );
  const tamperVerify = verifiableReportService.verifyReport(regTamper.report_id);
  assert.strictEqual(tamperVerify.status, 'INVALID');
  assert.strictEqual(tamperVerify.hash_matched, false);
  console.log(`  ✓ Tampering detected and flagged as INVALID`);

  // Test 7: Revocation
  console.log('Test 7: Revoking a report marks it as REVOKED...');
  const revokeRes = verifiableReportService.revokeReport(registered.report_id, 'Regulatory correction required', orgA);
  assert.strictEqual(revokeRes.success, true);
  const revokedVerify = verifiableReportService.verifyReport(registered.report_id);
  assert.strictEqual(revokedVerify.status, 'REVOKED');
  assert.strictEqual(revokedVerify.verified, false);
  assert.strictEqual(revokedVerify.revocation_reason, 'Regulatory correction required');
  console.log(`  ✓ Revoked status verified successfully`);

  // Test 8: Cross-tenant revocation prevention
  console.log('Test 8: Cross-tenant revocation isolation check...');
  const regB = verifiableReportService.registerReport({
    scan_id: 'FS-SCAN-ORG-B',
    organization_id: orgB,
    session: mockSession
  });
  const crossTenantRevoke = verifiableReportService.revokeReport(regB.report_id, 'Malicious revoke', orgA);
  assert.strictEqual(crossTenantRevoke.success, false);
  assert.ok(crossTenantRevoke.message.includes('Cross-tenant revocation forbidden'));
  console.log(`  ✓ Cross-tenant revocation successfully blocked`);

  // Test 9: Public API Endpoint HTTP Integration
  console.log('Test 9: Testing HTTP GET /api/reports/verify/:report_id...');
  const httpVerify = await request(app).get(`/api/reports/verify/${regB.report_id}`);
  assert.strictEqual(httpVerify.status, 200);
  assert.strictEqual(httpVerify.body.status, 'VALID');
  assert.strictEqual(httpVerify.body.report_id, regB.report_id);
  assert.strictEqual(httpVerify.body.engine_version, '8.3.0');
  assert.strictEqual(httpVerify.body.checklist_version, 'Vendor Compliance v4');
  console.log(`  ✓ HTTP verification endpoint responded with VALID status and metadata`);

  // Test 10: Zero-Knowledge Privacy Verification
  console.log('Test 10: Ensuring zero data leakage of confidential content in verification payload...');
  const payloadStr = JSON.stringify(httpVerify.body);
  assert.ok(!payloadStr.includes('extracted_text'), 'No extracted text');
  assert.ok(!payloadStr.includes('ocr_text'), 'No OCR text');
  assert.ok(!payloadStr.includes('pii_entities'), 'No PII entities');
  assert.ok(!payloadStr.includes('GSTIN'), 'No GSTIN leaked');
  assert.ok(!payloadStr.includes('PAN'), 'No PAN leaked');
  console.log(`  ✓ Zero-Knowledge privacy verified. No confidential document content leaked.`);

  console.log('\n========================================================================');
  console.log('  ALL 10 PHASE 9 VERIFIABLE AUDIT REPORT TESTS PASSED SUCCESSFULLY!    ');
  console.log('========================================================================\n');
}

runVerifiableReportTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Test suite failed with error:', err);
  process.exit(1);
});
