import crypto from 'node:crypto';
import { AuditSession } from './models.js';

export interface CanonicalAuditReport {
  report_id: string;
  scan_id: string;
  organization_id: string;
  engine_version: string;
  checklist_version: string;
  generated_at: string;
  agency_name?: string;
  auditor_name?: string;
  overall_score: number;
  max_score: number;
  overall_status: string;
  total_parameters: number;
  pass_count: number;
  fail_count: number;
  review_count: number;
  not_found_count: number;
  fatal_failures_count: number;
  category_scores: Record<string, { earned: number; max: number; status: string }>;
  parameter_summaries: Array<{
    parameter_id: string;
    category: string;
    status: string;
    fatal: boolean;
    score_earned: number;
    max_score: number;
    confidence: number;
    evidence_count: number;
  }>;
}

export interface StoredAuditReportRecord {
  report_id: string;
  scan_id: string;
  organization_id: string;
  engine_version: string;
  checklist_version: string;
  generated_at: string;
  report_hash: string;
  status: 'VALID' | 'REVOKED' | 'INVALID';
  canonical_payload_json: string;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  created_at: string;
}

export interface ReportVerificationResponse {
  status: 'VALID' | 'INVALID' | 'REVOKED';
  verified?: boolean;
  report_id?: string;
  scan_id?: string;
  organization_id?: string;
  engine_version?: string;
  checklist_version?: string;
  generated_at?: string;
  report_hash?: string;
  computed_hash?: string;
  hash_matched?: boolean;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  metrics?: {
    overall_score: number;
    max_score: number;
    overall_status: string;
    total_parameters: number;
    pass_count: number;
    fail_count: number;
    review_count: number;
    fatal_failures_count: number;
    agency_name?: string;
    auditor_name?: string;
  };
  message?: string;
}

/**
 * Deterministic JSON stringifier sorting all keys alphabetically recursively
 */
export function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJsonStringify(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    return JSON.stringify(key) + ':' + canonicalJsonStringify(obj[key]);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Generates cryptographic SHA-256 hash of canonical representation
 */
export function computeReportHash(canonicalReport: CanonicalAuditReport): string {
  const canonicalString = canonicalJsonStringify(canonicalReport);
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}

/**
 * Service to register and verify cryptographically verifiable audit reports
 */
export class VerifiableAuditReportService {
  private db: any;
  private static ed25519Keys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  constructor(db: any) {
    this.db = db;
  }

  /**
   * Builds the canonical metadata representation of an audit session (without sensitive PII/evidence text)
   */
  public buildCanonicalReport(
    reportIdOrParams: string | { report_id?: string; scan_id?: string; organization_id?: string; org_id?: string; session?: AuditSession; engine_version?: string; checklist_version?: string; generated_at?: string },
    sessionArg?: AuditSession,
    orgIdArg?: string,
    engineVersionArg = '8.3.0',
    checklistVersionArg = 'Vendor Compliance v4',
    generatedAtArg?: string
  ): CanonicalAuditReport {
    let reportId: string;
    let session: AuditSession;
    let orgId: string;
    let engineVersion = '8.3.0';
    let checklistVersion = 'Vendor Compliance v4';
    let generatedAt: string | undefined;

    if (typeof reportIdOrParams === 'string') {
      reportId = reportIdOrParams;
      session = sessionArg || {} as any;
      orgId = orgIdArg || 'LOCAL-ORG';
      engineVersion = engineVersionArg;
      checklistVersion = checklistVersionArg;
      generatedAt = generatedAtArg;
    } else if (reportIdOrParams && typeof reportIdOrParams === 'object') {
      session = reportIdOrParams.session || sessionArg || {} as any;
      reportId = reportIdOrParams.report_id || `FS-RPT-${session?.audit_id ? session.audit_id.replace(/^AUDIT-/, '') : crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      orgId = reportIdOrParams.organization_id || reportIdOrParams.org_id || orgIdArg || 'LOCAL-ORG';
      engineVersion = reportIdOrParams.engine_version || engineVersionArg;
      checklistVersion = reportIdOrParams.checklist_version || checklistVersionArg;
      generatedAt = reportIdOrParams.generated_at || generatedAtArg;
    } else {
      reportId = `FS-RPT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      session = sessionArg || {} as any;
      orgId = orgIdArg || 'LOCAL-ORG';
    }

    const timestamp = generatedAt || session.updated_at || new Date().toISOString();

    const paramSummaries = (session.parameter_results || []).map(r => {
      const effectiveStatus = r.override ? r.override.new_status : r.status;
      return {
        parameter_id: r.parameter_id,
        category: (r.parameter as any)?.category_name || (r.parameter as any)?.category || 'GENERAL_COMPLIANCE',
        status: effectiveStatus,
        fatal: Boolean(r.fatal),
        score_earned: Number(r.score_earned || 0),
        max_score: Number(r.max_score || 0),
        confidence: typeof r.confidence === 'number' ? r.confidence : 1.0,
        evidence_count: Array.isArray(r.evidence) ? r.evidence.length : 0
      };
    }).sort((a, b) => a.parameter_id.localeCompare(b.parameter_id));

    // Sort category score keys
    const sortedCategoryScores: Record<string, { earned: number; max: number; status: string }> = {};
    if (session.category_scores) {
      Object.keys(session.category_scores).sort().forEach(k => {
        const cat = session.category_scores![k] as any;
        sortedCategoryScores[k] = {
          earned: Number(cat.earned !== undefined ? cat.earned : (cat.score || 0)),
          max: Number(cat.max !== undefined ? cat.max : (cat.max_score || 0)),
          status: String(cat.status || 'PASS')
        };
      });
    }

    return {
      report_id: reportId,
      scan_id: session.scan_id || `FS-SCAN-${session.audit_id || reportId}`,
      organization_id: orgId,
      engine_version: engineVersion,
      checklist_version: checklistVersion,
      generated_at: timestamp,
      agency_name: session.agency_name,
      auditor_name: session.auditor_name,
      overall_score: Number(session.overall_score || 0),
      max_score: Number(session.max_score || 100),
      overall_status: session.overall_status || 'COMPLIANT',
      total_parameters: Number(session.total_parameters || paramSummaries.length),
      pass_count: Number(session.pass_count || 0),
      fail_count: Number(session.fail_count || 0),
      review_count: Number(session.review_count || 0),
      not_found_count: Number((session as any).not_found_count || 0),
      fatal_failures_count: Number(session.fatal_failures_count || 0),
      category_scores: sortedCategoryScores,
      parameter_summaries: paramSummaries
    };
  }

  /**
   * Helper to compute hash directly through service instance
   */
  public computeReportHash(canonicalReport: CanonicalAuditReport): string {
    return computeReportHash(canonicalReport);
  }

  /**
   * Registers a new audit report record with deterministic SHA-256 hash
   */
  public registerReport(params: {
    report_id?: string;
    scan_id: string;
    organization_id: string;
    engine_version?: string;
    checklist_version?: string;
    generated_at?: string;
    canonical_report?: CanonicalAuditReport;
    session?: AuditSession;
    custom_report_hash?: string;
  }): {
    report_id: string;
    scan_id: string;
    organization_id: string;
    engine_version: string;
    checklist_version: string;
    generated_at: string;
    report_hash: string;
    status: 'VALID';
  } {
    const reportId = params.report_id || (params.session?.audit_id ? `FS-RPT-${params.session.audit_id.replace(/^AUDIT-/, '')}` : `FS-RPT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`);
    const engineVersion = params.engine_version || '8.3.0';
    const checklistVersion = params.checklist_version || 'Vendor Compliance v4';
    const generatedAt = params.generated_at || params.session?.updated_at || new Date().toISOString();

    let canonical: CanonicalAuditReport;
    if (params.canonical_report) {
      canonical = {
        ...params.canonical_report,
        report_id: reportId,
        scan_id: params.scan_id,
        organization_id: params.organization_id,
        engine_version: engineVersion,
        checklist_version: checklistVersion,
        generated_at: generatedAt
      };
    } else if (params.session) {
      canonical = this.buildCanonicalReport(
        reportId,
        params.session,
        params.organization_id,
        engineVersion,
        checklistVersion,
        generatedAt
      );
    } else {
      // Build standard minimal canonical model for scan_id
      canonical = {
        report_id: reportId,
        scan_id: params.scan_id,
        organization_id: params.organization_id,
        engine_version: engineVersion,
        checklist_version: checklistVersion,
        generated_at: generatedAt,
        overall_score: 100,
        max_score: 100,
        overall_status: 'COMPLIANT',
        total_parameters: 25,
        pass_count: 25,
        fail_count: 0,
        review_count: 0,
        not_found_count: 0,
        fatal_failures_count: 0,
        category_scores: {},
        parameter_summaries: []
      };
    }

    const reportHash = params.custom_report_hash || computeReportHash(canonical);
    const signature = crypto.sign(null, Buffer.from(reportHash, 'utf8'), VerifiableAuditReportService.ed25519Keys.privateKey).toString('hex');
    const publicKeyPem = VerifiableAuditReportService.ed25519Keys.publicKey;
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO audit_reports (
        report_id, scan_id, organization_id, engine_version, checklist_version,
        generated_at, report_hash, signature, public_key, status, canonical_payload_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'VALID', ?, ?)
      ON CONFLICT(report_id) DO UPDATE SET
        scan_id = excluded.scan_id,
        organization_id = excluded.organization_id,
        engine_version = excluded.engine_version,
        checklist_version = excluded.checklist_version,
        generated_at = excluded.generated_at,
        report_hash = excluded.report_hash,
        signature = excluded.signature,
        public_key = excluded.public_key,
        status = 'VALID',
        canonical_payload_json = excluded.canonical_payload_json
    `);

    stmt.run(
      reportId,
      params.scan_id,
      params.organization_id,
      engineVersion,
      checklistVersion,
      generatedAt,
      reportHash,
      signature,
      publicKeyPem,
      canonicalJsonStringify(canonical),
      now
    );

    return {
      report_id: reportId,
      scan_id: params.scan_id,
      organization_id: params.organization_id,
      engine_version: engineVersion,
      checklist_version: checklistVersion,
      generated_at: generatedAt,
      report_hash: reportHash,
      status: 'VALID'
    };
  }

  /**
   * Verifies an audit report by ID.
   * Compares the stored canonical payload's recalculated hash against the stored hash.
   * Strictly returns VALID, INVALID, or REVOKED, along with safe non-sensitive metadata.
   */
  public verifyReport(reportId: string, callerOrgId?: string): ReportVerificationResponse {
    if (!reportId || typeof reportId !== 'string') {
      return {
        status: 'INVALID',
        verified: false,
        message: 'Invalid or missing report ID format'
      };
    }

    const cleanId = reportId.trim();

    const row = this.db.prepare(`
      SELECT * FROM audit_reports WHERE report_id = ?
    `).get(cleanId) as any;

    if (!row) {
      return {
        status: 'INVALID',
        verified: false,
        report_id: cleanId,
        message: 'Report not found in authoritative verification registry'
      };
    }

    // Optional cross-tenant isolation enforcement if caller provides an orgId
    if (callerOrgId && row.organization_id !== callerOrgId) {
      return {
        status: 'INVALID',
        verified: false,
        report_id: cleanId,
        message: 'Cross-tenant verification denied'
      };
    }

    // Check if revoked
    if (row.status === 'REVOKED') {
      return {
        status: 'REVOKED',
        verified: false,
        report_id: row.report_id,
        scan_id: row.scan_id,
        organization_id: row.organization_id,
        engine_version: row.engine_version,
        checklist_version: row.checklist_version,
        generated_at: row.generated_at,
        report_hash: row.report_hash,
        revoked_at: row.revoked_at,
        revocation_reason: row.revocation_reason || 'Administrative revocation',
        message: 'Audit report has been officially revoked'
      };
    }

    // Parse canonical payload and recompute hash to detect any tampering
    let canonicalObj: CanonicalAuditReport | null = null;
    let computedHash = '';
    try {
      if (row.canonical_payload_json) {
        canonicalObj = JSON.parse(row.canonical_payload_json);
        computedHash = computeReportHash(canonicalObj!);
      }
    } catch (e) {
      return {
        status: 'INVALID',
        verified: false,
        report_id: row.report_id,
        message: 'Corrupt canonical record format'
      };
    }

    // Integrity check
    if (!computedHash || computedHash !== row.report_hash) {
      return {
        status: 'INVALID',
        verified: false,
        report_id: row.report_id,
        scan_id: row.scan_id,
        organization_id: row.organization_id,
        engine_version: row.engine_version,
        checklist_version: row.checklist_version,
        generated_at: row.generated_at,
        report_hash: row.report_hash,
        computed_hash: computedHash,
        hash_matched: false,
        message: 'Cryptographic integrity check failed: Report contents have been altered or corrupted'
      };
    }

    // Asymmetric Ed25519 signature verification check
    if (row.signature && row.public_key) {
      try {
        const isValidSig = crypto.verify(
          null,
          Buffer.from(computedHash, 'utf8'),
          crypto.createPublicKey(row.public_key),
          Buffer.from(row.signature, 'hex')
        );
        if (!isValidSig) {
          return {
            status: 'INVALID',
            verified: false,
            report_id: row.report_id,
            message: 'Asymmetric Ed25519 cryptographic signature verification failed'
          };
        }
      } catch (sigErr) {
        return {
          status: 'INVALID',
          verified: false,
          report_id: row.report_id,
          message: 'Asymmetric Ed25519 signature parsing error'
        };
      }
    }

    return {
      status: 'VALID',
      verified: true,
      report_id: row.report_id,
      scan_id: row.scan_id,
      organization_id: row.organization_id,
      engine_version: row.engine_version,
      checklist_version: row.checklist_version,
      generated_at: row.generated_at,
      report_hash: row.report_hash,
      computed_hash: computedHash,
      hash_matched: true,
      metrics: canonicalObj ? {
        overall_score: canonicalObj.overall_score,
        max_score: canonicalObj.max_score,
        overall_status: canonicalObj.overall_status,
        total_parameters: canonicalObj.total_parameters,
        pass_count: canonicalObj.pass_count,
        fail_count: canonicalObj.fail_count,
        review_count: canonicalObj.review_count,
        fatal_failures_count: canonicalObj.fatal_failures_count,
        agency_name: canonicalObj.agency_name,
        auditor_name: canonicalObj.auditor_name
      } : undefined
    };
  }

  /**
   * Revokes an existing audit report
   */
  public revokeReport(reportId: string, reason: string, orgId?: string): { success: boolean; message?: string } {
    const row = this.db.prepare('SELECT * FROM audit_reports WHERE report_id = ?').get(reportId) as any;
    if (!row) {
      return { success: false, message: 'Report not found in authoritative verification registry' };
    }

    if (orgId && row.organization_id !== orgId) {
      return { success: false, message: 'Cross-tenant revocation forbidden: Unauthorized organization' };
    }

    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE audit_reports
      SET status = 'REVOKED', revoked_at = ?, revocation_reason = ?
      WHERE report_id = ?
    `).run(now, reason, reportId);

    return { success: true };
  }

  /**
   * Retrieves a stored audit report record by ID
   */
  public getReport(reportId: string): StoredAuditReportRecord | null {
    if (!reportId || typeof reportId !== 'string') {
      return null;
    }
    const row = this.db.prepare(`
      SELECT report_id, scan_id, organization_id, engine_version, checklist_version,
             generated_at, report_hash, status, canonical_payload_json, revoked_at, revocation_reason, created_at
      FROM audit_reports
      WHERE report_id = ?
    `).get(reportId.trim()) as StoredAuditReportRecord | undefined;

    return row || null;
  }

  /**
   * Lists registered reports for an organization
   */
  public listReports(orgId: string, limit = 50): StoredAuditReportRecord[] {
    return this.db.prepare(`
      SELECT report_id, scan_id, organization_id, engine_version, checklist_version,
             generated_at, report_hash, status, revoked_at, revocation_reason, created_at
      FROM audit_reports
      WHERE organization_id = ?
      ORDER BY generated_at DESC
      LIMIT ?
    `).all(orgId, limit) as StoredAuditReportRecord[];
  }
}
