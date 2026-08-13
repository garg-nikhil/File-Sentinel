import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getDatabase } from './db.js';
import { FileScannerEngine } from './scannerEngine.js';
import { getCloudStorageProvider } from './quarantineService.js';
import { analyzeContentWithGemini } from './gemini.js';
import { ensureSampleFilesExist } from './sample_data.js';
import { Rule, AppSettings, AuditEvent } from '../src/types.js';
import { EvidenceEngine } from './audit/evidenceEngine.js';
import { AuditReportGenerator } from './audit/auditReport.js';
import { INITIAL_AUDIT_CHECKLIST } from './audit/checklist.js';
import { AuditScoringEngine } from './audit/scoring.js';

export function createApiRouter() {
  const router = express.Router();
  const db = getDatabase();
  const scannerEngine = new FileScannerEngine(db);
  const cloudStorage = getCloudStorageProvider();

  // App Settings default state
  let currentSettings: AppSettings = {
    maxFileSizeMB: 50,
    maxScanDepth: 10,
    aiEnabled: true,
    cloudUploadEnabled: true,
    redactSensitivePreview: true,
    cloudBucketName: 'filesentinel-prod-quarantine',
    quarantineLocalDir: './storage_bucket/quarantine_staging'
  };

  // Ensure initial sample files exist on server boot
  ensureSampleFilesExist('./sample-files').catch(err => console.error('Sample files init error:', err));

  // Helper for audit logging
  function logAuditEvent(action: string, filePath?: string, sha256?: string, status: 'SUCCESS' | 'WARNING' | 'ERROR' = 'SUCCESS', details?: string) {
    try {
      const id = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
      const stmt = db.prepare(`
        INSERT INTO audit_events (id, timestamp, action, file_path, sha256, user_identity, status, details)
        VALUES (?, ?, ?, ?, ?, 'local-admin', ?, ?)
      `);
      stmt.run(id, new Date().toISOString(), action, filePath || null, sha256 || null, status, details || null);
    } catch (e) {
      console.error('Audit log write error:', e);
    }
  }

  // --- HEALTH & METRICS ---
  router.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'FileSentinel Engine',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      database: 'connected',
      sample_files: './sample-files'
    });
  });

  router.get('/settings', (req: Request, res: Response) => {
    res.json(currentSettings);
  });

  router.post('/settings', (req: Request, res: Response) => {
    currentSettings = { ...currentSettings, ...req.body };
    logAuditEvent('UPDATE_SETTINGS', undefined, undefined, 'SUCCESS', 'App configuration updated');
    res.json(currentSettings);
  });

  // --- SCANS ---
  router.post('/scans', async (req: Request, res: Response) => {
    const { root_path } = req.body;
    const targetPath = root_path || path.resolve('./sample-files');

    if (!fs.existsSync(targetPath)) {
      return res.status(400).json({ error: `Directory target does not exist: ${targetPath}` });
    }

    // Fetch active rules from DB
    const rows = db.prepare('SELECT * FROM rules WHERE enabled = 1').all() as any[];
    const activeRules: Rule[] = rows.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      enabled: Boolean(r.enabled),
      pattern: r.pattern,
      description: r.description,
      recommendation: r.recommendation,
      isBuiltIn: Boolean(r.is_builtin)
    }));

    const session = await scannerEngine.startScan(targetPath, activeRules, currentSettings);
    logAuditEvent('START_SCAN', targetPath, undefined, 'SUCCESS', `Scan ID: ${session.scan_id}`);

    res.json(session);
  });

  router.get('/scans', (req: Request, res: Response) => {
    const rows = db.prepare('SELECT * FROM scans ORDER BY start_time DESC LIMIT 50').all();
    res.json(rows);
  });

  router.get('/scans/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    // Check in-memory active session first
    const active = scannerEngine.getScanProgress(id);
    if (active) return res.json(active);

    const row = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'Scan session not found' });
    res.json(row);
  });

  router.get('/scans/:id/progress', (req: Request, res: Response) => {
    const { id } = req.params;
    const active = scannerEngine.getScanProgress(id);
    if (active) return res.json(active);

    const row = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'Scan session not found' });
    res.json(row);
  });

  // --- FILES ---
  router.get('/files', (req: Request, res: Response) => {
    const { scan_id, classification, severity } = req.query;
    let query = 'SELECT * FROM files';
    const params: any[] = [];
    const conditions: string[] = [];

    if (scan_id) {
      conditions.push('scan_id = ?');
      params.push(scan_id);
    }
    if (classification) {
      conditions.push('classification = ?');
      params.push(classification);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY risk_score DESC, file_id DESC LIMIT 200';

    const rows = db.prepare(query).all(...params) as any[];
    const parsedFiles = rows.map(f => {
      const findingsRows = db.prepare('SELECT * FROM findings WHERE file_id = ?').all(f.file_id) as any[];
      const findings = findingsRows.map(fRow => ({
        ...fRow,
        evidence: fRow.evidence_json ? JSON.parse(fRow.evidence_json) : {}
      }));

      const findings_count = {
        critical: findings.filter(x => x.severity === 'CRITICAL').length,
        high: findings.filter(x => x.severity === 'HIGH').length,
        medium: findings.filter(x => x.severity === 'MEDIUM').length,
        low: findings.filter(x => x.severity === 'LOW').length,
        info: findings.filter(x => x.severity === 'INFO').length
      };

      return {
        ...f,
        findings,
        findings_count,
        metadata: f.metadata_json ? JSON.parse(f.metadata_json) : {},
        warnings: f.warnings_json ? JSON.parse(f.warnings_json) : [],
        ai_summary: f.ai_summary_json ? JSON.parse(f.ai_summary_json) : undefined
      };
    });

    res.json(parsedFiles);
  });

  router.get('/files/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const row = db.prepare('SELECT * FROM files WHERE file_id = ?').get(id) as any;
    if (!row) return res.status(404).json({ error: 'File not found' });

    const findingsRows = db.prepare('SELECT * FROM findings WHERE file_id = ?').all(id) as any[];
    const findings = findingsRows.map(fRow => ({
      ...fRow,
      evidence: fRow.evidence_json ? JSON.parse(fRow.evidence_json) : {}
    }));

    res.json({
      ...row,
      findings,
      metadata: row.metadata_json ? JSON.parse(row.metadata_json) : {},
      warnings: row.warnings_json ? JSON.parse(row.warnings_json) : [],
      ai_summary: row.ai_summary_json ? JSON.parse(row.ai_summary_json) : undefined
    });
  });

  // AI Gemini trigger route for deep file evaluation
  router.post('/files/:id/analyze-ai', async (req: Request, res: Response) => {
    const { id } = req.params;
    const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(id) as any;
    if (!fileRow) return res.status(404).json({ error: 'File not found' });

    const findingsCount = db.prepare('SELECT COUNT(*) as count FROM findings WHERE file_id = ?').get(id) as { count: number };

    const aiResult = await analyzeContentWithGemini(
      fileRow.filename,
      fileRow.extension,
      fileRow.extracted_text_preview || '',
      findingsCount.count
    );

    if (aiResult) {
      db.prepare('UPDATE files SET ai_summary_json = ?, classification = ? WHERE file_id = ?')
        .run(JSON.stringify(aiResult), aiResult.classification, id);

      logAuditEvent('AI_ANALYSIS', fileRow.path, fileRow.sha256, 'SUCCESS', `AI Assigned classification: ${aiResult.classification}`);
      return res.json({ success: true, ai_summary: aiResult });
    }

    res.status(500).json({ error: 'AI evaluation unavailable or skipped due to missing API key.' });
  });

  // --- FINDINGS ---
  router.get('/findings', (req: Request, res: Response) => {
    const rows = db.prepare(`
      SELECT f.*, fi.filename, fi.path as file_path
      FROM findings f
      JOIN files fi ON f.file_id = fi.file_id
      ORDER BY 
        CASE f.severity
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3
          WHEN 'LOW' THEN 4
          ELSE 5
        END, f.created_at DESC
      LIMIT 300
    `).all() as any[];

    const findings = rows.map(r => ({
      ...r,
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : {}
    }));

    res.json(findings);
  });

  // --- RULES ---
  router.get('/rules', (req: Request, res: Response) => {
    const rows = db.prepare('SELECT * FROM rules ORDER BY category, id').all() as any[];
    const rules = rows.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      enabled: Boolean(r.enabled),
      pattern: r.pattern,
      description: r.description,
      recommendation: r.recommendation,
      isBuiltIn: Boolean(r.is_builtin)
    }));
    res.json(rules);
  });

  router.post('/rules', (req: Request, res: Response) => {
    const { id, name, category, severity, enabled, pattern, description, recommendation } = req.body;
    const newId = id || `RULE-${crypto.randomUUID().substring(0, 8)}`;

    const stmt = db.prepare(`
      INSERT INTO rules (id, name, category, severity, enabled, pattern, description, recommendation, is_builtin)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    `);
    stmt.run(newId, name, category, severity, enabled ? 1 : 0, pattern, description, recommendation);

    logAuditEvent('CREATE_RULE', undefined, undefined, 'SUCCESS', `Created custom rule: ${newId}`);
    res.json({ success: true, id: newId });
  });

  router.put('/rules/:id/toggle', (req: Request, res: Response) => {
    const { id } = req.params;
    const { enabled } = req.body;

    db.prepare('UPDATE rules SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, id);
    res.json({ success: true, id, enabled });
  });

  // --- QUARANTINE & VERIFIED CLOUD REMOVAL ---
  router.get('/quarantine', (req: Request, res: Response) => {
    const rows = db.prepare('SELECT * FROM quarantine_items ORDER BY quarantined_at DESC').all() as any[];
    const items = rows.map(r => ({
      ...r,
      logs: r.logs_json ? JSON.parse(r.logs_json) : []
    }));
    res.json(items);
  });

  router.post('/quarantine/:file_id', (req: Request, res: Response) => {
    const { file_id } = req.params;
    const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(file_id) as any;
    if (!fileRow) return res.status(404).json({ error: 'File not found' });

    const qId = `Q-${crypto.randomUUID().substring(0, 8)}`;
    const logs = [`[${new Date().toISOString()}] File staged in quarantine registry`];

    const stmt = db.prepare(`
      INSERT INTO quarantine_items (
        id, file_id, original_path, filename, sha256, size, cloud_object,
        upload_status, verification_status, deletion_status, quarantined_at, logs_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 'NOT_DELETED', ?, ?)
    `);

    stmt.run(
      qId,
      file_id,
      fileRow.path,
      fileRow.filename,
      fileRow.sha256,
      fileRow.size,
      `${fileRow.sha256}_${fileRow.filename}`,
      new Date().toISOString(),
      JSON.stringify(logs)
    );

    logAuditEvent('QUARANTINE_STAGE', fileRow.path, fileRow.sha256, 'SUCCESS', `Quarantine Item: ${qId}`);

    res.json({ success: true, quarantine_id: qId });
  });

  // CRITICAL UPLOAD AND SAFE REMOVE ROUTE
  router.post('/quarantine/:file_id/upload-and-remove', async (req: Request, res: Response) => {
    const { file_id } = req.params;
    const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(file_id) as any;
    if (!fileRow) return res.status(404).json({ error: 'File record not found' });

    // Check idempotency state machine
    const existingQ = db.prepare('SELECT * FROM quarantine_items WHERE file_id = ? ORDER BY quarantined_at DESC LIMIT 1').get(file_id) as any;
    if (existingQ) {
      if (existingQ.upload_status === 'UPLOADING' || existingQ.deletion_status === 'DELETING' || existingQ.deletion_status === 'DELETED') {
        return res.status(409).json({
          success: false,
          error: `Operation already in progress or completed (upload_status: ${existingQ.upload_status}, deletion_status: ${existingQ.deletion_status})`,
          state: existingQ.deletion_status === 'DELETED' ? 'DELETED' : existingQ.upload_status
        });
      }
    }

    const localPath = fileRow.path;
    const sha256 = fileRow.sha256;
    const cloudObjectName = `${sha256}_${fileRow.filename}`;
    const logs: string[] = [];

    const addLog = (msg: string) => {
      logs.push(`[${new Date().toISOString()}] ${msg}`);
    };

    const qId = existingQ ? existingQ.id : `Q-${crypto.randomUUID().substring(0, 8)}`;
    const nowStr = new Date().toISOString();

    if (!existingQ) {
      db.prepare(`
        INSERT INTO quarantine_items (
          id, file_id, original_path, filename, sha256, size, cloud_object,
          upload_status, verification_status, deletion_status, quarantined_at, logs_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'UPLOADING', 'PENDING', 'PENDING', ?, ?)
      `).run(qId, file_id, localPath, fileRow.filename, sha256, fileRow.size, cloudObjectName, nowStr, JSON.stringify(logs));
    } else {
      db.prepare(`
        UPDATE quarantine_items
        SET upload_status = 'UPLOADING', logs_json = ?
        WHERE id = ?
      `).run(JSON.stringify(logs), qId);
    }

    addLog(`Initiating Upload & Remove pipeline for file: ${localPath}`);

    // STEP 1: Local file existence and SHA-256 recalculation check
    if (!fs.existsSync(localPath)) {
      addLog(`ERROR: Local file missing at path ${localPath}. Operation aborted.`);
      db.prepare(`UPDATE quarantine_items SET upload_status = 'UPLOAD_FAILED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
      return res.status(400).json({ success: false, logs, error: 'Local file missing before upload' });
    }

    const currentHash = scannerEngine.calculateSHA256(localPath);
    if (currentHash !== sha256) {
      addLog(`ERROR: File SHA-256 hash mismatch! Original: ${sha256}, Current: ${currentHash}`);
      db.prepare(`UPDATE quarantine_items SET upload_status = 'UPLOAD_FAILED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
      return res.status(400).json({ success: false, logs, error: 'SHA-256 checksum verification failed' });
    }
    addLog(`Local pre-upload checksum verified: ${sha256}`);

    // STEP 2: Upload to Cloud Storage
    addLog(`Uploading object '${cloudObjectName}' to cloud bucket...`);
    const uploadOk = await cloudStorage.upload(localPath, cloudObjectName);
    if (!uploadOk) {
      addLog('ERROR: Cloud storage upload failed or returned non-success response.');
      addLog('PROTECTION RULE ENFORCED: Local file remains UNTOUCHED.');
      logAuditEvent('CLOUD_UPLOAD_FAILED', localPath, sha256, 'ERROR', 'Upload failure. Local file preserved.');
      db.prepare(`UPDATE quarantine_items SET upload_status = 'UPLOAD_FAILED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
      return res.status(500).json({ success: false, logs, error: 'Cloud upload failed. Local file was preserved.' });
    }
    addLog('Cloud upload request returned success.');
    db.prepare(`UPDATE quarantine_items SET upload_status = 'UPLOADED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);

    // STEP 3: Verification of Remote Cloud Object Identity
    addLog('Verifying remote object existence and matching SHA-256 hash in cloud...');
    const verifiedOk = await cloudStorage.verify(cloudObjectName, sha256);

    if (!verifiedOk) {
      addLog('ERROR: Cloud verification failed! Object not found or hash mismatch in cloud.');
      addLog('PROTECTION RULE ENFORCED: Local file remains UNTOUCHED.');
      logAuditEvent('CLOUD_VERIFY_FAILED', localPath, sha256, 'ERROR', 'Verification failure. Local file preserved.');
      db.prepare(`UPDATE quarantine_items SET verification_status = 'VERIFICATION_FAILED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
      return res.status(500).json({ success: false, logs, error: 'Cloud verification failed. Local file was preserved.' });
    }
    addLog('Cloud object verified successfully! Remote SHA-256 matches local identity.');
    db.prepare(`UPDATE quarantine_items SET verification_status = 'VERIFIED', verified_at = ?, logs_json = ? WHERE id = ?`).run(new Date().toISOString(), JSON.stringify(logs), qId);

    // STEP 4: Local Deletion ONLY after Verified Upload
    addLog('Proceeding to local file deletion step...');
    db.prepare(`UPDATE quarantine_items SET deletion_status = 'DELETING', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
    let localDeleted = false;
    try {
      fs.unlinkSync(localPath);
      localDeleted = !fs.existsSync(localPath);
    } catch (e: any) {
      addLog(`ERROR deleting local file: ${e.message}`);
    }

    if (!localDeleted) {
      addLog('WARNING: Local deletion execution failed or file still exists on disk.');
      logAuditEvent('LOCAL_DELETE_FAILED', localPath, sha256, 'WARNING', 'Cloud verified, but local deletion failed.');
      db.prepare(`UPDATE quarantine_items SET deletion_status = 'DELETION_FAILED', logs_json = ? WHERE id = ?`).run(JSON.stringify(logs), qId);
      return res.status(500).json({ success: false, logs, error: 'Cloud upload verified, but local file deletion failed.' });
    }

    addLog('SUCCESS: Local file verified deleted from disk.');
    logAuditEvent('VERIFIED_UPLOAD_AND_DELETE', localPath, sha256, 'SUCCESS', 'File safely stored in cloud and removed locally.');

    db.prepare(`UPDATE quarantine_items SET deletion_status = 'DELETED', deleted_at = ?, logs_json = ? WHERE id = ?`).run(new Date().toISOString(), JSON.stringify(logs), qId);

    res.json({
      success: true,
      quarantine_id: qId,
      cloud_object: cloudObjectName,
      local_deleted: true,
      logs
    });
  });

  // --- DASHBOARD STATS ---
  router.get('/dashboard/stats', (req: Request, res: Response) => {
    const totalScans = (db.prepare('SELECT COUNT(*) as c FROM scans').get() as any).c;
    const totalFilesScanned = (db.prepare('SELECT COUNT(*) as c FROM files').get() as any).c;

    const critical = (db.prepare("SELECT COUNT(*) as c FROM files WHERE risk_score >= 80").get() as any).c;
    const high = (db.prepare("SELECT COUNT(*) as c FROM files WHERE risk_score >= 50 AND risk_score < 80").get() as any).c;
    const medium = (db.prepare("SELECT COUNT(*) as c FROM files WHERE risk_score >= 20 AND risk_score < 50").get() as any).c;
    const low = (db.prepare("SELECT COUNT(*) as c FROM files WHERE risk_score > 0 AND risk_score < 20").get() as any).c;
    const safe = (db.prepare("SELECT COUNT(*) as c FROM files WHERE risk_score = 0").get() as any).c;

    const recentScans = db.prepare('SELECT * FROM scans ORDER BY start_time DESC LIMIT 5').all();
    const highestRiskFiles = db.prepare('SELECT * FROM files ORDER BY risk_score DESC LIMIT 5').all();
    const recentFindings = db.prepare('SELECT f.*, fi.filename FROM findings f JOIN files fi ON f.file_id = fi.file_id ORDER BY created_at DESC LIMIT 6').all();

    res.json({
      totalScans,
      totalFilesScanned,
      riskBreakdown: { critical, high, medium, low, safe },
      quarantinedCount: (db.prepare('SELECT COUNT(*) as c FROM quarantine_items').get() as any).c,
      recentScans,
      highestRiskFiles,
      recentFindings
    });
  });

  // AUDIT LOGS
  router.get('/audit-logs', (req: Request, res: Response) => {
    const rows = db.prepare('SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 100').all();
    res.json(rows);
  });

  // --- AUDIT COMPLIANCE ENDPOINTS ---
  const evidenceEngine = new EvidenceEngine(db);

  // Trigger Audit Compliance Scan
  router.post('/audit/run', async (req: Request, res: Response) => {
    try {
      const { target_dir, audit_date, agency_name, auditor_name } = req.body;
      const targetDir = target_dir || path.resolve('./sample-files');

      if (!fs.existsSync(targetDir)) {
        return res.status(400).json({ error: `Directory target does not exist: ${targetDir}` });
      }

      // Collect file paths
      const filePaths: string[] = [];
      function collectFiles(dir: string) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) collectFiles(fullPath);
          else filePaths.push(fullPath);
        }
      }
      collectFiles(targetDir);

      const session = await evidenceEngine.runAuditScan(
        filePaths,
        audit_date || new Date().toISOString().split('T')[0],
        agency_name || 'Primary Telecalling & Collection Agency',
        auditor_name || 'Automated Compliance Inspector'
      );

      logAuditEvent('RUN_AUDIT_COMPLIANCE', targetDir, undefined, 'SUCCESS', `Audit ID: ${session.audit_id}, Score: ${session.overall_score}`);
      res.json(session);
    } catch (err: any) {
      console.error('[API] Audit run error:', err);
      res.status(500).json({ error: err.message || 'Audit execution failed' });
    }
  });

  // List past audit sessions
  router.get('/audit/sessions', (req: Request, res: Response) => {
    try {
      const rows = db.prepare('SELECT * FROM audit_sessions ORDER BY created_at DESC LIMIT 50').all() as any[];
      const sessions = rows.map(r => ({
        ...r,
        category_scores: r.category_scores_json ? JSON.parse(r.category_scores_json) : {}
      }));
      res.json(sessions);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get specific audit session details with parameters and evidence
  router.get('/audit/session/:id', (req: Request, res: Response) => {
    try {
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];

      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => {
        const checklistParam = activeChecklistMap.get(pr.parameter_id) || {
          id: pr.parameter_id,
          category: 'ZERO_TOLERANCE',
          category_name: 'Audit Parameter',
          category_weight: 100,
          parameter: pr.parameter_id,
          fatal: Boolean(pr.fatal),
          severity: 'HIGH',
          required_evidence: [],
          keywords: [],
          logic: 'SINGLE',
          evaluation_rules: [],
          enabled: true
        };

        return {
          parameter_id: pr.parameter_id,
          parameter: checklistParam,
          status: pr.status,
          confidence: pr.confidence,
          fatal: Boolean(pr.fatal),
          score_earned: pr.score_earned,
          max_score: pr.max_score,
          policy_status: pr.policy_status,
          pv_status: pr.pv_status,
          evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],
          reason: pr.reason,
          missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
          warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
          ai_recommendation: pr.ai_recommendation_json ? JSON.parse(pr.ai_recommendation_json) : undefined,
          override: pr.override_json ? JSON.parse(pr.override_json) : undefined
        };
      });

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults
      };

      res.json(session);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Auditor Override Endpoint
  router.post('/audit/override', (req: Request, res: Response) => {
    try {
      const { audit_id, parameter_id, new_status, auditor_name, comment } = req.body;

      if (!audit_id || !parameter_id || !new_status || !auditor_name) {
        return res.status(400).json({ error: 'Missing required override fields' });
      }

      // Fetch existing result
      const row = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ? AND parameter_id = ?').get(audit_id, parameter_id) as any;
      if (!row) {
        return res.status(404).json({ error: 'Audit parameter result not found' });
      }

      const override = {
        original_status: row.status,
        new_status,
        auditor_name,
        comment: comment || 'Manual auditor override applied',
        timestamp: new Date().toISOString()
      };

      // Update parameter result in DB
      db.prepare(`
        UPDATE audit_parameter_results
        SET override_json = ?
        WHERE audit_id = ? AND parameter_id = ?
      `).run(JSON.stringify(override), audit_id, parameter_id);

      // Recalculate Audit Session Scores
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(audit_id) as any;
      const allParamRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(audit_id) as any[];

      const checklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const fullResults = allParamRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: checklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        policy_status: pr.policy_status,
        pv_status: pr.pv_status,
        evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const updatedSession = AuditScoringEngine.calculateAuditSummary(
        audit_id,
        sessionRow.agency_name,
        sessionRow.auditor_name,
        sessionRow.audit_date,
        fullResults as any
      );

      // Save updated totals to session
      db.prepare(`
        UPDATE audit_sessions
        SET pass_count = ?, fail_count = ?, review_count = ?, not_found_count = ?,
            fatal_failures_count = ?, overall_score = ?, overall_status = ?,
            category_scores_json = ?, updated_at = ?
        WHERE audit_id = ?
      `).run(
        updatedSession.pass_count,
        updatedSession.fail_count,
        updatedSession.review_count,
        updatedSession.not_found_count,
        updatedSession.fatal_failures_count,
        updatedSession.overall_score,
        updatedSession.overall_status,
        JSON.stringify(updatedSession.category_scores),
        new Date().toISOString(),
        audit_id
      );

      logAuditEvent('AUDITOR_OVERRIDE', audit_id, undefined, 'SUCCESS', `Parameter ${parameter_id} overridden to ${new_status} by ${auditor_name}`);

      res.json({ success: true, override, session: updatedSession });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get Active Checklist Parameters
  router.get('/audit/checklist', (req: Request, res: Response) => {
    res.json(INITIAL_AUDIT_CHECKLIST);
  });

  // Get Evidence Gaps
  router.get('/audit/gaps/:id', (req: Request, res: Response) => {
    try {
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];
      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: activeChecklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults
      };

      const gaps = evidenceEngine.generateEvidenceGaps(session as any);
      res.json(gaps);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Export Audit Report
  router.get('/audit/report/:id/:format', (req: Request, res: Response) => {
    try {
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];
      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: activeChecklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        policy_status: pr.policy_status,
        pv_status: pr.pv_status,
        evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults
      };

      const format = req.params.format.toLowerCase();
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="AuditReport_${session.audit_id}.json"`);
        return res.send(AuditReportGenerator.generateJson(session as any));
      } else if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="AuditReport_${session.audit_id}.csv"`);
        return res.send(AuditReportGenerator.generateCsv(session as any));
      } else {
        res.setHeader('Content-Type', 'text/html');
        return res.send(AuditReportGenerator.generateHtml(session as any));
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}
