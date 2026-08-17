import crypto from 'node:crypto';
import { defaultRegistry } from '../extractors/registry.js';
import { INITIAL_AUDIT_CHECKLIST } from './checklist.js';
import { DateEvaluator } from './dateEvaluator.js';
import { EvidenceMatcher, calculateEvidencePriority, enrichEvidenceItemWithMetricsAndRole } from './evidenceMatcher.js';
import { AuditEvaluator } from './evaluator.js';
import { evaluateEvidenceWithGemini } from './aiClassifier.ts';
import { AuditScoringEngine } from './scoring.js';
import { EntityResolver } from './entityResolver.js';
import {
  AuditGap,
  AuditParameter,
  AuditParameterResult,
  AuditSession,
  EvidenceGap,
  EvidenceItem
} from './models.js';

export interface RunAuditScanForSessionOptions {
  scanId: string;
  orgId: string;
  auditDate?: string;
  agencyName?: string;
  auditorName?: string;
  customChecklist?: AuditParameter[];
}

export class EvidenceEngine {
  private db: any;
  private matcher: EvidenceMatcher;
  private evaluator: AuditEvaluator;

  constructor(db: any) {
    this.db = db;
    this.matcher = new EvidenceMatcher();
    this.evaluator = new AuditEvaluator();
  }

  /**
   * Runs an Audit Scan over discovered/scanned files for a specific directory or existing database files
   */
  public async runAuditScan(
    filePaths: string[],
    auditDate: string = new Date().toISOString().split('T')[0],
    agencyName: string = 'Primary Telecalling & Collection Agency',
    auditorName: string = 'Automated Audit System',
    customChecklist?: AuditParameter[],
    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF',
    orgId?: string
  ): Promise<AuditSession> {
    const auditId = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
    const activeChecklist = customChecklist || INITIAL_AUDIT_CHECKLIST;

    console.log(`[Audit Engine] Starting Audit ${auditId} over ${filePaths.length} files with date ${auditDate}`);

    // Extract text and metadata for all target files
    const fileExtractions: { fileId: string; filePath: string; extraction: any }[] = [];

    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i];
      const fileId = `FILE-${crypto.randomUUID().substring(0, 8)}`;
      try {
        const extraction = await defaultRegistry.extract(filePath, 50);
        fileExtractions.push({ fileId, filePath, extraction });
      } catch (err) {
        console.warn(`[Audit Engine] Failed extracting file ${filePath}:`, err);
      }
    }

    return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, undefined, aiPrivacyMode, orgId);
  }

  /**
   * Runs an Audit Scan over existing scan session data (already extracted evidence)
   */
  public async runAuditScanForSession(options: RunAuditScanForSessionOptions): Promise<AuditSession> {
    const {
      scanId,
      orgId,
      auditDate = new Date().toISOString().split('T')[0],
      agencyName = 'Primary Telecalling & Collection Agency',
      auditorName = 'Automated Audit System',
      customChecklist
    } = options;

    if (!scanId || typeof scanId !== 'string') {
      throw new Error('Scan ID is required for audit scan');
    }
    if (!orgId || typeof orgId !== 'string') {
      throw new Error('Organization ID is mandatory for audit scan');
    }

    const scanRow = this.db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(scanId) as any;
    if (!scanRow || scanRow.org_id !== orgId) {
      throw new Error('Access denied: Cross-tenant audit scan forbidden');
    }

    const auditId = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
    const activeChecklist = customChecklist || INITIAL_AUDIT_CHECKLIST;
    
    console.log(`[Audit Engine] Starting Audit ${auditId} for Scan Session ${scanId} (Org: ${orgId})`);

    const rows = this.db.prepare('SELECT file_id, path, extracted_text, metadata_json FROM files WHERE scan_id = ?').all(scanId) as any[];
    
    const fileExtractions: { fileId: string; filePath: string; extraction: any }[] = [];
    
    for (const row of rows) {
      let metadata = {};
      try {
        if (row.metadata_json) {
          metadata = JSON.parse(row.metadata_json);
        }
      } catch(e) {}
      
      fileExtractions.push({
        fileId: row.file_id,
        filePath: row.path,
        extraction: {
          text: row.extracted_text || '',
          metadata: metadata
        }
      });
    }
    
    return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, scanId, 'OFF', orgId);
  }

  private async evaluateChecklist(
    auditId: string,
    fileExtractions: { fileId: string; filePath: string; extraction: any }[],
    activeChecklist: AuditParameter[],
    auditDate: string,
    agencyName: string,
    auditorName: string,
    scanId?: string,
    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF',
    orgId?: string
  ): Promise<AuditSession> {
    // Evaluate each parameter against all documents
    const parameterResults: AuditParameterResult[] = [];

    for (const param of activeChecklist) {
      if (!param.enabled) continue;

      const matchedEvidence: EvidenceItem[] = [];

      for (const item of fileExtractions) {
        const matched = this.matcher.matchDocumentToParameter(
          item.fileId,
          item.filePath,
          item.extraction,
          param
        );
        if (matched) {
          matchedEvidence.push(matched);
        }
      }

      // Sort evidence by multi-factor candidate priority
      matchedEvidence.sort((a, b) => calculateEvidencePriority(b, param) - calculateEvidencePriority(a, param));
      const enrichedEvidence = matchedEvidence.map((ev, index) => {
        const isPrimary = index === 0 && ev.validated;
        const isDuplicateOrParallel = index > 0 && ev.validated;
        return enrichEvidenceItemWithMetricsAndRole(ev, param, undefined, isPrimary, isDuplicateOrParallel);
      });

      // Deterministic Evaluation
      const result = this.evaluator.evaluateParameter(param, enrichedEvidence, auditDate);

      // Optional Gemini AI Assistance
      if (aiPrivacyMode !== 'OFF' && result.evidence_set && (result.evidence_set.primaryEvidence || result.evidence_set.supportingEvidence.length > 0)) {
        try {
          const evidenceForAi = {
             primary: result.evidence_set.primaryEvidence,
             supporting: result.evidence_set.supportingEvidence,
             contradictory: result.evidence_set.contradictoryEvidence
          };
          
          let aiText = '';
          if (aiPrivacyMode === 'FULL_TEXT') {
            const topFile = fileExtractions.find(f => f.fileId === result.evidence_set?.primaryEvidence?.file_id);
            aiText = topFile?.extraction?.text || '';
          } else {
             aiText = JSON.stringify(evidenceForAi, null, 2);
          }

          const filename = result.evidence_set?.primaryEvidence?.filename || 'aggregated_evidence.json';

          const aiRec = await evaluateEvidenceWithGemini(
            filename,
            aiText,
            param
          );
          if (aiRec) {
            result.ai_recommendation = aiRec;
          }
        } catch {
          // Silently fall back to deterministic evaluation result
        }
      }

      parameterResults.push(result);
    }

    // Compute Overall Scoring and Summary
    const session = AuditScoringEngine.calculateAuditSummary(
      auditId,
      agencyName,
      auditorName,
      auditDate,
      parameterResults
    );
    if (scanId) {
      session.scan_id = scanId;
    }
    if (orgId) {
      (session as any).org_id = orgId;
    }

    // Perform True Session-Level Entity Resolution across all validated evidence
    const entityResolution = EntityResolver.resolveAuditSessionEntities(parameterResults, auditId);
    session.entities = entityResolution.entities;
    session.entity_conflicts = entityResolution.conflicts;
    session.entity_findings = entityResolution.entityFindings;
    session.entity_resolution = entityResolution;
    session.entityConflicts = entityResolution.conflicts;
    session.entityFindings = entityResolution.entityFindings;
    session.entityResolution = entityResolution;

    // If entity conflicts exist and overall status was compliant, flag that review is needed
    if (entityResolution.conflicts.length > 0 && session.overall_status === 'COMPLIANT') {
      session.overall_status = 'NEEDS_REVIEW';
    }

    this.saveAuditSessionToDb(session);

    return session;
  }

  /**
   * Generates actionable Evidence Gaps list for remediation planning
   */
  public generateEvidenceGaps(session: AuditSession): EvidenceGap[] {
    const gaps: EvidenceGap[] = [];
    if (!session.parameter_results) return gaps;

    for (const res of session.parameter_results) {
      const status = res.override ? res.override.new_status : res.status;
      if (status === 'FAIL' || status === 'REVIEW' || status === 'EVIDENCE_NOT_FOUND') {
        let priority: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
        if (res.fatal) priority = 'HIGH';
        else if (status === 'FAIL') priority = 'HIGH';
        else if (status === 'EVIDENCE_NOT_FOUND') priority = 'MEDIUM';
        else priority = 'LOW';

        gaps.push({
          priority,
          parameter_id: res.parameter_id,
          parameter_title: res.parameter.parameter,
          category: res.parameter.category_name,
          fatal: res.fatal,
          status,
          missing: res.missing_requirements.join(', ') || 'Acceptable operational evidence',
          recommended_action: res.parameter.evaluation_rules[0] || 'Provide verified documentary evidence',
          fatal_impact: res.fatal && (status === 'FAIL' || status === 'EVIDENCE_NOT_FOUND')
        });
      }
    }

    return gaps;
  }

  /**
   * Persists Audit Session and parameter results in SQLite
   */
  private saveAuditSessionToDb(session: AuditSession): void {
    if (!this.db) return;

    try {
      let orgId = (session as any).org_id || null;
      if (session.scan_id) {
        const scanRow = this.db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(session.scan_id) as any;
        if (scanRow && scanRow.org_id) {
          if (orgId && scanRow.org_id !== orgId) {
            throw new Error(`Tenant mismatch: audit_sessions.org_id (${orgId}) does not match scans.org_id (${scanRow.org_id})`);
          }
          if (!orgId) {
            orgId = scanRow.org_id;
          }
        }
      }

      const stmt = this.db.prepare(`
        INSERT INTO audit_sessions (
          audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status,
          total_parameters, pass_count, fail_count, review_count, not_found_count,
          fatal_failures_count, overall_score, max_score, overall_status,
          category_scores_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        session.audit_id,
        session.scan_id || null,
        orgId,
        session.audit_date,
        session.agency_name,
        session.auditor_name,
        session.status,
        session.total_parameters,
        session.pass_count,
        session.fail_count,
        session.review_count,
        session.not_found_count,
        session.fatal_failures_count,
        session.overall_score,
        session.max_score,
        session.overall_status,
        JSON.stringify(session.category_scores),
        session.created_at,
        session.updated_at
      );

      const paramStmt = this.db.prepare(`
        INSERT INTO audit_parameter_results (
          audit_id, parameter_id, status, confidence, fatal,
          score_earned, max_score, policy_status, pv_status,
          evidence_json, reason, missing_requirements_json, warnings_json,
          ai_recommendation_json, override_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      if (session.parameter_results) {
        for (const res of session.parameter_results) {

          // Sanitize evidence before saving to DB
          const sanitizedEvidence = res.evidence.map(e => {
            const safeItem = { ...e };
            if (safeItem.extracted_fields) {
               safeItem.extracted_fields = { ...safeItem.extracted_fields };
               delete safeItem.extracted_fields.raw_text;
               delete safeItem.extracted_fields.fullText;
               delete safeItem.extracted_fields.documentText;
               delete safeItem.extracted_fields.extractedText;
               delete safeItem.extracted_fields.text;
            }
            if (safeItem.structured_fields) {
               safeItem.structured_fields = { ...safeItem.structured_fields };
               delete safeItem.structured_fields.raw_text;
               delete safeItem.structured_fields.fullText;
               delete safeItem.structured_fields.documentText;
               delete safeItem.structured_fields.extractedText;
               delete safeItem.structured_fields.text;
            }
            return safeItem;
          });

          // Also sanitize evidence_set
          let sanitizedEvidenceSet = undefined;
          if (res.evidence_set) {
            const sanitizeList = (list) => list.map(e => {
               const safeItem = { ...e };
               if (safeItem.extracted_fields) {
                  safeItem.extracted_fields = { ...safeItem.extracted_fields };
                  delete safeItem.extracted_fields.raw_text;
               }
               return safeItem;
            });
            sanitizedEvidenceSet = {
               ...res.evidence_set,
               primaryEvidence: res.evidence_set.primaryEvidence ? sanitizeList([res.evidence_set.primaryEvidence])[0] : null,
               supportingEvidence: sanitizeList(res.evidence_set.supportingEvidence || []),
               reviewEvidence: sanitizeList(res.evidence_set.reviewEvidence || []),
               contradictoryEvidence: sanitizeList(res.evidence_set.contradictoryEvidence || []),
               rejectedCandidates: sanitizeList(res.evidence_set.rejectedCandidates || [])
            };
          }

          paramStmt.run(
            session.audit_id,
            res.parameter_id,
            res.status,
            res.confidence,
            res.fatal ? 1 : 0,
            res.score_earned,
            res.max_score,
            res.policy_status || null,
            res.pv_status || null,
            JSON.stringify({ evidence: sanitizedEvidence, evidence_set: sanitizedEvidenceSet }),
            res.reason,
            JSON.stringify(res.missing_requirements),
            JSON.stringify(res.warnings),
            res.ai_recommendation ? JSON.stringify(res.ai_recommendation) : null,
            res.override ? JSON.stringify(res.override) : null
          );
        }
      }

      // Save Entities
      if (session.entities && session.entities.length > 0) {
        const entityStmt = this.db.prepare(`
          INSERT OR REPLACE INTO audit_entities (
            entity_id, audit_id, entity_type, display_name, normalized_name,
            identifiers_json, evidence_references_json, matching_signals_json,
            confidence, status, conflicts_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const ent of session.entities) {
          entityStmt.run(
            ent.entityId,
            session.audit_id,
            ent.entityType,
            ent.displayName,
            ent.normalizedName,
            JSON.stringify(ent.identifiers),
            JSON.stringify(ent.evidenceReferences),
            JSON.stringify(ent.matchingSignals),
            ent.confidence,
            ent.status,
            JSON.stringify(ent.conflicts),
            ent.createdAt
          );
        }
      }

      // Save Entity Conflicts
      if (session.entity_conflicts && session.entity_conflicts.length > 0) {
        const conflictStmt = this.db.prepare(`
          INSERT INTO audit_entity_conflicts (
            id, audit_id, entity_id, conflict_type, severity,
            title, description, reason, involved_evidence_json,
            conflicting_attributes_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const conf of session.entity_conflicts) {
          conflictStmt.run(
            `CONF-${crypto.randomUUID().substring(0, 8)}`,
            session.audit_id,
            conf.involvedEvidence[0]?.fileId || 'UNKNOWN_ENTITY',
            conf.conflictType,
            conf.severity,
            conf.title,
            conf.description,
            conf.reason,
            JSON.stringify(conf.involvedEvidence),
            JSON.stringify(conf.conflictingAttributes),
            new Date().toISOString()
          );
        }
      }
    } catch (err) {
      console.error('[Audit Engine] Database save error:', err);
    }
  }
}
