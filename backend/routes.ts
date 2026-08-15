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
import { isValidFileId } from './securityMiddleware.js';

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

    try {
      if (!fs.existsSync(targetPath)) {
        return res.status(400).json({ error: `Directory target does not exist: ${targetPath}` });
      }
      const realTarget = fs.realpathSync(targetPath);
      const baseAllowed = process.env.BASE_ALLOWED_DIR ? fs.realpathSync(process.env.BASE_ALLOWED_DIR) : null;
      if (baseAllowed) {
        const rel = path.relative(baseAllowed, realTarget);
        if (rel === '..' || rel.startsWith('..' + path.sep) || rel.startsWith('../') || rel.startsWith('..\\') || path.isAbsolute(rel)) {
          return res.status(403).json({ error: `Access denied: Requested path is outside allowed directory.` });
        }
      }
    } catch (e: any) {
      return res.status(400).json({ error: `Directory target cannot be resolved: ${targetPath}` });
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

  // CRITICAL CORRECTION: Local file deletion route disabled and removed completely (Phase 6A: local files must never be deleted).
  router.post('/quarantine/:file_id/upload-and-remove', (req: Request, res: Response) => {
    return res.status(404).json({ error: 'Endpoint disabled or not supported. Local files are never deleted.' });
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

      // Load entities and conflicts
      let entities: any[] = [];
      let entityConflicts: any[] = [];
      try {
        const entityRows = db.prepare('SELECT * FROM audit_entities WHERE audit_id = ?').all(req.params.id) as any[];
        entities = entityRows.map(e => ({
          ...e,
          identifiers: e.identifiers_json ? JSON.parse(e.identifiers_json) : {},
          evidenceReferences: e.evidence_references_json ? JSON.parse(e.evidence_references_json) : [],
          matchingSignals: e.matching_signals_json ? JSON.parse(e.matching_signals_json) : [],
          conflicts: e.conflicts_json ? JSON.parse(e.conflicts_json) : []
        }));

        const conflictRows = db.prepare('SELECT * FROM audit_entity_conflicts WHERE audit_id = ?').all(req.params.id) as any[];
        entityConflicts = conflictRows.map(c => ({
          ...c,
          involvedEvidence: c.involved_evidence_json ? JSON.parse(c.involved_evidence_json) : [],
          conflictingAttributes: c.conflicting_attributes_json ? JSON.parse(c.conflicting_attributes_json) : {}
        }));
      } catch (e) {
        // Fallback gracefully if table not yet queried
      }

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults,
        entities,
        entity_conflicts: entityConflicts,
        entityConflicts
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

  // --- PHASE 6A: CLOUD UPLOAD ONLY / NON-DESTRUCTIVE QUARANTINE ---
  router.get('/cloud-uploads', (req: Request, res: Response) => {
    try {
      const rows = db.prepare('SELECT * FROM file_cloud_uploads').all();
      res.json(rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  async function processFileUpload(fileId: string): Promise<any> {
    const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId) as any;
    if (!fileRow) {
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: 'File not found' };
    }

    const localPath = fileRow.path;
    const sha256 = fileRow.sha256;
    const bucketName = process.env.GOOGLE_CLOUD_BUCKET || 'filesentinel-quarantine-bucket';
    const sanitizedFilename = path.basename(localPath).replace(/[^a-zA-Z0-9_.-]/g, '_');
    const cloudObjectName = `filesentinel/${fileRow.scan_id || 'general'}/${fileId}/${sanitizedFilename}`;

    const existingUpload = db.prepare('SELECT * FROM file_cloud_uploads WHERE file_id = ?').get(fileId) as any;
    if (existingUpload && existingUpload.upload_status === 'UPLOADED') {
      const verified = await cloudStorage.verify(cloudObjectName, sha256);
      if (verified) {
        return {
          file_id: fileId,
          filename: fileRow.filename,
          success: true,
          status: 'ALREADY_UPLOADED',
          cloud_object_name: cloudObjectName,
          sha256,
          local_file_retained: fs.existsSync(localPath)
        };
      }
    }

    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO file_cloud_uploads (file_id, scan_id, audit_session_id, original_filename, local_path, sha256, size, cloud_bucket, cloud_object_name, upload_status, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UPLOADING', ?)
      ON CONFLICT(file_id) DO UPDATE SET upload_status = 'UPLOADING', uploaded_at = ?
    `).run(fileId, fileRow.scan_id, null, fileRow.filename, localPath, sha256, fileRow.size, bucketName, cloudObjectName, now, now);

    logAuditEvent('UPLOAD_STARTED', localPath, sha256, 'SUCCESS', `Started upload for ${fileRow.filename}`);

    if (!fs.existsSync(localPath)) {
      const errMsg = 'Local file missing before upload';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
    }

    const currentHash = scannerEngine.calculateSHA256(localPath);
    if (currentHash !== sha256) {
      const errMsg = 'SHA-256 checksum mismatch';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
    }

    const uploadSuccess = await cloudStorage.upload(localPath, cloudObjectName);
    if (!uploadSuccess) {
      const errMsg = 'Cloud storage upload failed';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
    }

    logAuditEvent('UPLOAD_SUCCESS', localPath, sha256, 'SUCCESS', `Uploaded to ${cloudObjectName}`);

    const verified = await cloudStorage.verify(cloudObjectName, sha256);
    if (!verified) {
      const errMsg = 'Cloud verification failed or hash mismatch';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'VERIFICATION_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_VERIFICATION_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'VERIFICATION_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
    }

    const verifiedAt = new Date().toISOString();
    db.prepare(`
      UPDATE file_cloud_uploads
      SET upload_status = 'UPLOADED', verified_at = ?, error_message = NULL
      WHERE file_id = ?
    `).run(verifiedAt, fileId);

    logAuditEvent('UPLOAD_VERIFICATION_SUCCESS', localPath, sha256, 'SUCCESS', `Verified remote object ${cloudObjectName}`);

    const localFileExists = fs.existsSync(localPath);

    return {
      file_id: fileId,
      filename: fileRow.filename,
      success: true,
      status: 'UPLOADED',
      cloud_object_name: cloudObjectName,
      sha256,
      local_file_retained: localFileExists
    };
  }

  router.post('/cloud-uploads/upload', async (req: Request, res: Response) => {
    try {
      const { file_ids } = req.body;
      if (!Array.isArray(file_ids) || file_ids.length === 0) {
        return res.status(400).json({ error: 'file_ids array is required' });
      }

      if (file_ids.length > 500) {
        return res.status(400).json({ error: 'Batch size exceeds maximum allowed limit (500 files).' });
      }

      for (const fileId of file_ids) {
        if (!isValidFileId(fileId)) {
          return res.status(400).json({ error: `Invalid file ID format or security violation: ${fileId}` });
        }
      }

      const results: any[] = [];
      for (const fileId of file_ids) {
        const resItem = await processFileUpload(fileId);
        results.push(resItem);
      }

      const successCount = results.filter(r => r.success || r.status === 'ALREADY_UPLOADED').length;
      const failedCount = results.length - successCount;

      res.json({
        success: failedCount === 0,
        total_selected: results.length,
        success_count: successCount,
        failed_count: failedCount,
        results
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/cloud-uploads/upload-all', async (req: Request, res: Response) => {
    try {
      const { scan_id } = req.body;
      let query = 'SELECT file_id FROM files';
      const params: any[] = [];
      if (scan_id) {
        if (typeof scan_id !== 'string' || scan_id.length > 64) {
          return res.status(400).json({ error: 'Invalid scan_id parameter' });
        }
        query += ' WHERE scan_id = ?';
        params.push(scan_id);
      }
      const fileRows = db.prepare(query).all(...params) as any[];
      const fileIds = fileRows.map(r => r.file_id);

      if (fileIds.length > 5000) {
        return res.status(400).json({ error: 'Upload-all batch limit exceeded (max 5000 files).' });
      }

      const results: any[] = [];
      for (const fileId of fileIds) {
        const resItem = await processFileUpload(fileId);
        results.push(resItem);
      }

      const successCount = results.filter(r => r.success || r.status === 'ALREADY_UPLOADED').length;
      const failedCount = results.length - successCount;

      res.json({
        success: failedCount === 0,
        total_scanned: results.length,
        success_count: successCount,
        failed_count: failedCount,
        results
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/cloud-uploads/retry/:file_id', async (req: Request, res: Response) => {
    try {
      const { file_id } = req.params;
      if (!isValidFileId(file_id)) {
        return res.status(400).json({ error: 'Invalid file ID format or security violation.' });
      }
      const result = await processFileUpload(file_id);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}
