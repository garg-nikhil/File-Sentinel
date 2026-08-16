import fs from 'fs';
import path from 'path';
import { EvidenceEngine } from '../backend/audit/evidenceEngine.js';
import { DatabaseSync } from 'node:sqlite';
import { defaultRegistry } from '../backend/extractors/registry.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';

async function runTests() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE audit_sessions (
      audit_id TEXT PRIMARY KEY,
      agency_name TEXT,
      audit_date TEXT,
      overall_status TEXT,
      category_scores_json TEXT,
      updated_at TEXT, created_at TEXT
    );
    CREATE TABLE audit_parameter_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      audit_id TEXT,
      parameter_id TEXT,
      overall_status TEXT,
      confidence REAL,
      fatal INTEGER,
      score_earned REAL,
      max_score REAL,
      policy_overall_status TEXT,
      pv_overall_status TEXT,
      evidence_json TEXT,
      reason TEXT,
      missing_requirements_json TEXT,
      warnings_json TEXT,
      ai_recommendation_json TEXT,
      override_json TEXT
    );
    CREATE TABLE scanned_files (
      file_audit_id TEXT PRIMARY KEY,
      scan_id TEXT,
      original_path TEXT,
      filename TEXT,
      extracted_text TEXT,
      overall_status TEXT,
      updated_at TEXT, created_at TEXT
    );
    CREATE TABLE audit_entity_conflicts (
      audit_id TEXT PRIMARY KEY,
      audit_id TEXT,
      entity_id TEXT,
      conflict_type TEXT,
      severity TEXT,
      title TEXT,
      description TEXT,
      reason TEXT,
      involved_evidence_json TEXT,
      conflicting_attributes_json TEXT,
      updated_at TEXT, created_at TEXT
    );
  `);

  const engine = new EvidenceEngine(db as any);

  // MOCK defaultRegistry
  const originalExtract = defaultRegistry.extract.bind(defaultRegistry);
  defaultRegistry.extract = async (filePath) => {
    if (filePath.includes('mock_')) {
      const content = fs.readFileSync(filePath, 'utf8');
      return { text: content, pages: 1, metadata: {} };
    }
    return originalExtract(filePath);
  };

  const testDir = path.resolve('tests/phase_8_2_mocks');
  if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

  const zti008 = INITIAL_AUDIT_CHECKLIST.filter(p => p.id === 'ZTI-008');

  // Test A - Multiple evidence same control
  fs.writeFileSync(path.join(testDir, 'mock_usb_1.csv'), 'endpoint,policy,usb_storage,gpo_status,last_applied\nE1,USB,BLOCKED,APPLIED,2026-08-10');
  fs.writeFileSync(path.join(testDir, 'mock_usb_2.csv'), 'endpoint,policy,usb_storage,gpo_status,last_applied\nE2,USB,BLOCKED,APPLIED,2026-08-10');
  fs.writeFileSync(path.join(testDir, 'mock_usb_3.csv'), 'endpoint,policy,usb_storage,gpo_status,last_applied\nE3,USB,BLOCKED,APPLIED,2026-08-10');

  const session1 = await engine.runAuditScan(
    [
      path.join(testDir, 'mock_usb_1.csv'),
      path.join(testDir, 'mock_usb_2.csv'),
      path.join(testDir, 'mock_usb_3.csv')
    ],
    '2026-08-15',
    'Test Agency',
    'Automated Test',
    zti008
  );

  const zti008Result = session1.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
  console.assert(zti008Result !== undefined, 'ZTI-008 result must exist');
  
  const evSet = (zti008Result as any).evidence_set;
  console.assert(evSet !== undefined, 'Evidence Set must exist');
  console.log("TEST A: Primary Evidence:", evSet.primaryEvidence?.filename);
  console.log("TEST A: Supporting Evidence count:", evSet.supportingEvidence?.length);
  console.assert(evSet.supportingEvidence?.length === 2, 'Should have 2 supporting evidence files');
  
  // Test D - Contradictory evidence
  fs.writeFileSync(path.join(testDir, 'mock_usb_block.csv'), 'endpoint,policy,usb_storage,gpo_status\nE1,USB,BLOCKED,APPLIED');
  fs.writeFileSync(path.join(testDir, 'mock_usb_allow.csv'), 'endpoint,policy,usb_storage,gpo_status\nE1,USB,ALLOWED,APPLIED');
  
  const session2 = await engine.runAuditScan(
    [
      path.join(testDir, 'mock_usb_block.csv'),
      path.join(testDir, 'mock_usb_allow.csv'),
    ],
    '2026-08-15',
    'Test Agency',
    'Automated Test',
    zti008
  );

  const zti008Result2 = session2.parameter_results?.find(p => p.parameter_id === 'ZTI-008');
  const evSet2 = (zti008Result2 as any).evidence_set;
  console.log("TEST D: Contradictory Evidence count:", evSet2?.contradictoryEvidence?.length);
  console.assert(evSet2?.contradictoryEvidence?.length === 2, 'Should have 2 contradictory evidence files');
  console.assert(zti008Result2?.status === 'REVIEW', 'Status should be REVIEW due to contradiction');

  // Restore
  defaultRegistry.extract = originalExtract;
  console.log("ALL PHASE 8.2 TESTS PASSED.");
}

runTests().catch(console.error);
