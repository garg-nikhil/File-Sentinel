import os from 'node:os';
import crypto from 'node:crypto';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export interface DeviceTelemetry {
  device_id: string;
  os_family: string;
  os_version: string;
  architecture: string;
  filesentinel_version: string;
  coarse_resource_profile?: {
    cpu_cores_bucket: string;
    memory_gb_bucket: string;
  };
}

export interface ScanTelemetryPayload {
  scan_id: string;
  organization_id: string;
  user_id: string;
  device_id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  application_version: string;
  engine_version: string;
  checklist_version: string;
  files_discovered: number;
  files_processed: number;
  files_succeeded: number;
  files_failed: number;
  files_rejected_by_resource_limits: number;
  pass_count: number;
  review_count: number;
  fail_count: number;
  evidence_not_found_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  overall_score: number;
  parameters_evaluated: number;
  scan_status: string;
  device_telemetry?: DeviceTelemetry;
  debug_filenames_opt_in?: boolean;
  debug_filenames?: string[];
}

export interface TelemetryQueueItem {
  queue_id: string;
  scan_id: string;
  organization_id: string;
  payload: ScanTelemetryPayload;
  status: 'PENDING' | 'SYNCED' | 'FAILED';
  attempts: number;
  last_attempt_at?: string;
  error_message?: string;
  created_at: string;
  synced_at?: string;
}

export function collectDeviceTelemetry(deviceId: string): DeviceTelemetry {
  const cores = os.cpus()?.length || 1;
  const totalMemGB = Math.round(os.totalmem() / (1024 * 1024 * 1024));

  // Coarse bucketing for privacy (no exact memory/CPU footprint)
  const cpuBucket = cores <= 2 ? '1-2 cores' : cores <= 4 ? '4 cores' : cores <= 8 ? '8 cores' : '16+ cores';
  const memBucket = totalMemGB <= 4 ? '<=4 GB' : totalMemGB <= 8 ? '8 GB' : totalMemGB <= 16 ? '16 GB' : '32+ GB';

  return {
    device_id: deviceId,
    os_family: os.platform(), // e.g. 'linux', 'win32', 'darwin'
    os_version: os.release(),  // e.g. '5.15.0' (kernel/OS release only)
    architecture: os.arch(),   // e.g. 'x64', 'arm64'
    filesentinel_version: '1.0.0',
    coarse_resource_profile: {
      cpu_cores_bucket: cpuBucket,
      memory_gb_bucket: memBucket
    }
  };
}

export class TelemetryService {
  private db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  /**
   * Constructs a strictly privacy-preserving telemetry payload from scan and audit records.
   * ABSOLUTE PRIVACY GUARANTEE: Zero document text, zero OCR output, zero PII, zero full file paths.
   */
  public buildTelemetryPayload(
    scanId: string,
    orgId: string,
    userId: string,
    deviceId: string,
    options?: {
      debugFilenamesEnabled?: boolean;
      applicationVersion?: string;
      engineVersion?: string;
      checklistVersion?: string;
    }
  ): ScanTelemetryPayload | null {
    try {
      const scanRow = this.db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;
      if (!scanRow) {
        return null;
      }

      // Check for audit session attached to this scan
      const auditRow = this.db.prepare('SELECT * FROM audit_sessions WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1').get(scanId) as any;

      // Extract timing
      const startedAt = scanRow.start_time || new Date().toISOString();
      const completedAt = scanRow.end_time || new Date().toISOString();
      const startTimeMs = new Date(startedAt).getTime();
      const endTimeMs = new Date(completedAt).getTime();
      const durationMs = Math.max(0, endTimeMs - startTimeMs);

      // Extract file metrics
      const filesDiscovered = Number(scanRow.total_files || 0);
      const filesProcessed = Number(scanRow.processed_files || 0);
      const filesFailed = Number(scanRow.error_count || 0);
      const filesSucceeded = Math.max(0, filesProcessed - filesFailed);

      // Check resource limit rejected files if available
      let filesRejectedLimits = 0;
      try {
        const rej = this.db.prepare("SELECT COUNT(*) as count FROM files WHERE scan_id = ? AND warnings_json LIKE '%LIMIT%'").get(scanId) as any;
        filesRejectedLimits = Number(rej?.count || 0);
      } catch {}

      // Extract audit compliance metrics if available
      let passCount = 0;
      let reviewCount = 0;
      let failCount = 0;
      let evidenceNotFoundCount = 0;
      let overallScore = 0;
      let parametersEvaluated = 0;

      if (auditRow) {
        passCount = Number(auditRow.pass_count || 0);
        reviewCount = Number(auditRow.review_count || 0);
        failCount = Number(auditRow.fail_count || 0);
        evidenceNotFoundCount = Number(auditRow.not_found_count || 0);
        overallScore = Number(auditRow.overall_score || 0);
        parametersEvaluated = Number(auditRow.total_parameters || 0);
      }

      // Extract risk severity counts
      const criticalCount = Number(scanRow.critical_count || 0);
      const highCount = Number(scanRow.high_count || 0);
      const mediumCount = Number(scanRow.medium_count || 0);
      const lowCount = Number(scanRow.low_count || 0);

      // Device Telemetry
      const deviceTelemetry = collectDeviceTelemetry(deviceId);

      // Explicit Opt-in Debug Filenames
      const debugFilenamesOptIn = Boolean(options?.debugFilenamesEnabled);
      let debugFilenames: string[] | undefined = undefined;

      if (debugFilenamesOptIn) {
        try {
          const fileRows = this.db.prepare('SELECT filename FROM files WHERE scan_id = ? LIMIT 50').all(scanId) as any[];
          // Mask filenames, folders, path details, and local absolute paths for cloud privacy:
          debugFilenames = fileRows.map(r => {
            const rawName = String(r.filename || 'unknown_file');
            const baseName = path.basename(rawName);
            const ext = path.extname(baseName);
            const hashedBase = crypto.createHash('sha1').update(baseName).digest('hex').substring(0, 12);
            return `file_${hashedBase}${ext}`;
          });
        } catch {}
      }

      return {
        scan_id: scanId,
        organization_id: orgId,
        user_id: userId,
        device_id: deviceId,
        started_at: startedAt,
        completed_at: completedAt,
        duration_ms: durationMs,
        application_version: options?.applicationVersion || '1.0.0',
        engine_version: options?.engineVersion || '1.0.0',
        checklist_version: options?.checklistVersion || '2026.1',
        files_discovered: filesDiscovered,
        files_processed: filesProcessed,
        files_succeeded: filesSucceeded,
        files_failed: filesFailed,
        files_rejected_by_resource_limits: filesRejectedLimits,
        pass_count: passCount,
        review_count: reviewCount,
        fail_count: failCount,
        evidence_not_found_count: evidenceNotFoundCount,
        critical_count: criticalCount,
        high_count: highCount,
        medium_count: mediumCount,
        low_count: lowCount,
        overall_score: overallScore,
        parameters_evaluated: parametersEvaluated,
        scan_status: scanRow.status || 'COMPLETED',
        device_telemetry: deviceTelemetry,
        debug_filenames_opt_in: debugFilenamesOptIn,
        debug_filenames: debugFilenames
      };
    } catch (err) {
      console.error('[Telemetry] Error building telemetry payload:', err);
      return null;
    }
  }

  /**
   * Enqueues a telemetry payload to the local offline SQLite queue
   */
  public enqueue(payload: ScanTelemetryPayload): string {
    const queueId = `TQ-${crypto.randomUUID().substring(0, 8)}`;
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO telemetry_queue (
        queue_id, scan_id, organization_id, payload_json, status, attempts, created_at
      ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?)
    `);

    stmt.run(
      queueId,
      payload.scan_id,
      payload.organization_id,
      JSON.stringify(payload),
      now
    );

    return queueId;
  }

  /**
   * Records scan telemetry into the server-authoritative telemetry table with strict idempotency.
   * Idempotency boundary: (organization_id, scan_id)
   */
  public recordScanTelemetry(
    payload: ScanTelemetryPayload,
    clientIp?: string
  ): { success: boolean; scan_id: string; idempotent: boolean; message?: string } {
    // Validate required fields
    if (!payload.scan_id || !payload.organization_id || !payload.user_id || !payload.device_id) {
      throw new Error('Missing mandatory identification fields in scan telemetry payload');
    }
    if (typeof payload.duration_ms !== 'number' || payload.duration_ms < 0) {
      throw new Error('Invalid duration_ms in scan telemetry payload');
    }
    if (typeof payload.files_discovered !== 'number' || payload.files_discovered < 0) {
      throw new Error('Invalid files_discovered in scan telemetry payload');
    }
    if (!payload.started_at || !payload.completed_at) {
      throw new Error('Missing timestamp boundaries in scan telemetry payload');
    }

    const now = new Date().toISOString();
    const existing = this.db.prepare(`
      SELECT scan_id, organization_id FROM scan_telemetry WHERE organization_id = ? AND scan_id = ?
    `).get(payload.organization_id, payload.scan_id) as any;

    if (existing) {
      // Idempotent update
      const updateStmt = this.db.prepare(`
        UPDATE scan_telemetry SET
          user_id = ?,
          device_id = ?,
          started_at = ?,
          completed_at = ?,
          duration_ms = ?,
          application_version = ?,
          engine_version = ?,
          checklist_version = ?,
          files_discovered = ?,
          files_processed = ?,
          files_succeeded = ?,
          files_failed = ?,
          files_rejected_by_resource_limits = ?,
          pass_count = ?,
          review_count = ?,
          fail_count = ?,
          evidence_not_found_count = ?,
          critical_count = ?,
          high_count = ?,
          medium_count = ?,
          low_count = ?,
          overall_score = ?,
          parameters_evaluated = ?,
          scan_status = ?,
          device_telemetry_json = ?,
          debug_filenames_opt_in = ?,
          ip_address = COALESCE(?, ip_address)
        WHERE organization_id = ? AND scan_id = ?
      `);

      updateStmt.run(
        payload.user_id,
        payload.device_id,
        payload.started_at,
        payload.completed_at,
        payload.duration_ms,
        payload.application_version || '1.0.0',
        payload.engine_version || '1.0.0',
        payload.checklist_version || '2026.1',
        payload.files_discovered ?? 0,
        payload.files_processed ?? 0,
        payload.files_succeeded ?? 0,
        payload.files_failed ?? 0,
        payload.files_rejected_by_resource_limits ?? 0,
        payload.pass_count ?? 0,
        payload.review_count ?? 0,
        payload.fail_count ?? 0,
        payload.evidence_not_found_count ?? 0,
        payload.critical_count ?? 0,
        payload.high_count ?? 0,
        payload.medium_count ?? 0,
        payload.low_count ?? 0,
        payload.overall_score ?? 0,
        payload.parameters_evaluated ?? 0,
        payload.scan_status,
        payload.device_telemetry ? JSON.stringify(payload.device_telemetry) : null,
        payload.debug_filenames_opt_in ? 1 : 0,
        clientIp || null,
        payload.organization_id,
        payload.scan_id
      );

      return {
        success: true,
        scan_id: payload.scan_id,
        idempotent: true,
        message: 'Telemetry acknowledged (idempotent update)'
      };
    }

    // Insert new record
    const insertStmt = this.db.prepare(`
      INSERT INTO scan_telemetry (
        scan_id, organization_id, user_id, device_id, started_at, completed_at, duration_ms,
        application_version, engine_version, checklist_version, files_discovered,
        files_processed, files_succeeded, files_failed, files_rejected_by_resource_limits,
        pass_count, review_count, fail_count, evidence_not_found_count, critical_count,
        high_count, medium_count, low_count, overall_score, parameters_evaluated,
        scan_status, device_telemetry_json, debug_filenames_opt_in, created_at, ip_address
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?
      )
    `);

    insertStmt.run(
      payload.scan_id,
      payload.organization_id,
      payload.user_id,
      payload.device_id,
      payload.started_at,
      payload.completed_at,
      payload.duration_ms,
      payload.application_version || '1.0.0',
      payload.engine_version || '1.0.0',
      payload.checklist_version || '2026.1',
      payload.files_discovered ?? 0,
      payload.files_processed ?? 0,
      payload.files_succeeded ?? 0,
      payload.files_failed ?? 0,
      payload.files_rejected_by_resource_limits ?? 0,
      payload.pass_count ?? 0,
      payload.review_count ?? 0,
      payload.fail_count ?? 0,
      payload.evidence_not_found_count ?? 0,
      payload.critical_count ?? 0,
      payload.high_count ?? 0,
      payload.medium_count ?? 0,
      payload.low_count ?? 0,
      payload.overall_score ?? 0,
      payload.parameters_evaluated ?? 0,
      payload.scan_status,
      payload.device_telemetry ? JSON.stringify(payload.device_telemetry) : null,
      payload.debug_filenames_opt_in ? 1 : 0,
      now,
      clientIp || null
    );

    return {
      success: true,
      scan_id: payload.scan_id,
      idempotent: false,
      message: 'Telemetry recorded successfully'
    };
  }

  /**
   * Synchronizes / flushes pending items in the offline queue
   */
  public flushQueue(): { processed: number; succeeded: number; failed: number } {
    const pending = this.db.prepare(`
      SELECT * FROM telemetry_queue WHERE status = 'PENDING' OR (status = 'FAILED' AND attempts < 5) ORDER BY created_at ASC
    `).all() as any[];

    let succeeded = 0;
    let failed = 0;

    for (const item of pending) {
      try {
        const payload: ScanTelemetryPayload = JSON.parse(item.payload_json);
        this.recordScanTelemetry(payload);

        // Mark as synced
        const now = new Date().toISOString();
        this.db.prepare(`
          UPDATE telemetry_queue SET
            status = 'SYNCED',
            synced_at = ?,
            error_message = NULL,
            attempts = attempts + 1,
            last_attempt_at = ?
          WHERE queue_id = ?
        `).run(now, now, item.queue_id);

        succeeded++;
      } catch (err: any) {
        failed++;
        const now = new Date().toISOString();
        this.db.prepare(`
          UPDATE telemetry_queue SET
            status = 'FAILED',
            error_message = ?,
            attempts = attempts + 1,
            last_attempt_at = ?
          WHERE queue_id = ?
        `).run(err.message || 'Unknown flush error', now, item.queue_id);
      }
    }

    return { processed: pending.length, succeeded, failed };
  }

  /**
   * Retrieves scan history for an organization
   */
  public getScanHistory(orgId: string, limit: number = 50, offset: number = 0): ScanTelemetryPayload[] {
    const rows = this.db.prepare(`
      SELECT * FROM scan_telemetry
      WHERE organization_id = ?
      ORDER BY started_at DESC
      LIMIT ? OFFSET ?
    `).all(orgId, limit, offset) as any[];

    return rows.map(r => ({
      scan_id: r.scan_id,
      organization_id: r.organization_id,
      user_id: r.user_id,
      device_id: r.device_id,
      started_at: r.started_at,
      completed_at: r.completed_at,
      duration_ms: r.duration_ms,
      application_version: r.application_version,
      engine_version: r.engine_version,
      checklist_version: r.checklist_version,
      files_discovered: r.files_discovered,
      files_processed: r.files_processed,
      files_succeeded: r.files_succeeded,
      files_failed: r.files_failed,
      files_rejected_by_resource_limits: r.files_rejected_by_resource_limits,
      pass_count: r.pass_count,
      review_count: r.review_count,
      fail_count: r.fail_count,
      evidence_not_found_count: r.evidence_not_found_count,
      critical_count: r.critical_count,
      high_count: r.high_count,
      medium_count: r.medium_count,
      low_count: r.low_count,
      overall_score: r.overall_score,
      parameters_evaluated: r.parameters_evaluated,
      scan_status: r.scan_status,
      device_telemetry: r.device_telemetry_json ? JSON.parse(r.device_telemetry_json) : undefined,
      debug_filenames_opt_in: Boolean(r.debug_filenames_opt_in)
    }));
  }

  /**
   * Retrieves a single scan telemetry record by scanId and orgId
   */
  public getScanTelemetry(orgId: string, scanId: string): ScanTelemetryPayload | null {
    const r = this.db.prepare(`
      SELECT * FROM scan_telemetry
      WHERE organization_id = ? AND scan_id = ?
    `).get(orgId, scanId) as any;

    if (!r) return null;

    return {
      scan_id: r.scan_id,
      organization_id: r.organization_id,
      user_id: r.user_id,
      device_id: r.device_id,
      started_at: r.started_at,
      completed_at: r.completed_at,
      duration_ms: r.duration_ms,
      application_version: r.application_version,
      engine_version: r.engine_version,
      checklist_version: r.checklist_version,
      files_discovered: r.files_discovered,
      files_processed: r.files_processed,
      files_succeeded: r.files_succeeded,
      files_failed: r.files_failed,
      files_rejected_by_resource_limits: r.files_rejected_by_resource_limits,
      pass_count: r.pass_count,
      review_count: r.review_count,
      fail_count: r.fail_count,
      evidence_not_found_count: r.evidence_not_found_count,
      critical_count: r.critical_count,
      high_count: r.high_count,
      medium_count: r.medium_count,
      low_count: r.low_count,
      overall_score: r.overall_score,
      parameters_evaluated: r.parameters_evaluated,
      scan_status: r.scan_status,
      device_telemetry: r.device_telemetry_json ? JSON.parse(r.device_telemetry_json) : undefined,
      debug_filenames_opt_in: Boolean(r.debug_filenames_opt_in)
    };
  }

  /**
   * Retrieves dashboard overview metrics for an organization
   */
  public getDashboardOverview(orgId: string) {
    const scans = this.db.prepare(`
      SELECT scan_id, started_at, completed_at, duration_ms, overall_score,
             files_processed, pass_count, review_count, fail_count,
             evidence_not_found_count, critical_count, high_count, medium_count, low_count,
             parameters_evaluated, scan_status
      FROM scan_telemetry
      WHERE organization_id = ?
      ORDER BY started_at DESC
    `).all(orgId) as any[];

    if (scans.length === 0) {
      return {
        total_scans: 0,
        current_score: 0,
        previous_score: 0,
        score_change: 0,
        last_scan: null,
        files_scanned: 0,
        pass_count: 0,
        review_count: 0,
        fail_count: 0,
        evidence_not_found_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0
      };
    }

    const latest = scans[0];
    const previous = scans.length > 1 ? scans[1] : null;

    const currentScore = latest.overall_score || 0;
    const previousScore = previous ? (previous.overall_score || 0) : currentScore;
    const scoreChange = Number((currentScore - previousScore).toFixed(1));

    // Aggregate totals across all organization scans
    let totalFiles = 0;
    let totalPass = 0;
    let totalReview = 0;
    let totalFail = 0;
    let totalNotFound = 0;
    let totalCritical = 0;
    let totalHigh = 0;
    let totalMedium = 0;
    let totalLow = 0;

    for (const s of scans) {
      totalFiles += s.files_processed || 0;
      totalPass += s.pass_count || 0;
      totalReview += s.review_count || 0;
      totalFail += s.fail_count || 0;
      totalNotFound += s.evidence_not_found_count || 0;
      totalCritical += s.critical_count || 0;
      totalHigh += s.high_count || 0;
      totalMedium += s.medium_count || 0;
      totalLow += s.low_count || 0;
    }

    return {
      total_scans: scans.length,
      current_score: currentScore,
      previous_score: previousScore,
      score_change: scoreChange,
      last_scan: latest.completed_at || latest.started_at,
      last_scan_id: latest.scan_id,
      files_scanned: totalFiles,
      pass_count: totalPass,
      review_count: totalReview,
      fail_count: totalFail,
      evidence_not_found_count: totalNotFound,
      critical_count: totalCritical,
      high_count: totalHigh,
      medium_count: totalMedium,
      low_count: totalLow,
      latest_breakdown: {
        pass_count: latest.pass_count,
        review_count: latest.review_count,
        fail_count: latest.fail_count,
        evidence_not_found_count: latest.evidence_not_found_count,
        critical_count: latest.critical_count,
        high_count: latest.high_count,
        medium_count: latest.medium_count,
        low_count: latest.low_count
      }
    };
  }

  /**
   * Retrieves score compliance trend points over time for an organization
   */
  public getComplianceTrend(orgId: string, limit: number = 30) {
    const rows = this.db.prepare(`
      SELECT scan_id, started_at, completed_at, overall_score, files_processed,
             pass_count, review_count, fail_count, critical_count, high_count
      FROM scan_telemetry
      WHERE organization_id = ?
      ORDER BY started_at ASC
      LIMIT ?
    `).all(orgId, limit) as any[];

    return rows.map(r => ({
      scan_id: r.scan_id,
      date: r.completed_at || r.started_at,
      score: r.overall_score,
      files: r.files_processed,
      pass: r.pass_count,
      review: r.review_count,
      fail: r.fail_count,
      critical: r.critical_count,
      high: r.high_count
    }));
  }

  /**
   * Verifies report metadata authenticity against server scan_telemetry and audit_sessions
   */
  public verifyReport(orgId: string, queryId: string) {
    const cleanId = queryId.trim();
    
    // Check scan_telemetry first
    const tele = this.db.prepare(`
      SELECT * FROM scan_telemetry WHERE (scan_id = ? OR scan_id LIKE ?)
    `).get(cleanId, `%${cleanId}%`) as any;

    if (!tele) {
      // Also check audit_sessions table
      const audit = this.db.prepare(`
        SELECT a.*, s.org_id FROM audit_sessions a
        LEFT JOIN scans s ON a.scan_id = s.scan_id
        WHERE a.audit_id = ? OR a.scan_id = ?
      `).get(cleanId, cleanId) as any;

      if (!audit) {
        return {
          verified: false,
          match_status: 'NOT_FOUND',
          message: 'Report identifier could not be located in server audit records.'
        };
      }

      // Check organization isolation
      if (audit.org_id && audit.org_id !== orgId) {
        return {
          verified: false,
          match_status: 'UNAUTHORIZED_ORGANIZATION',
          message: 'Access Denied: Report belongs to a different organization domain.'
        };
      }

      return {
        verified: true,
        match_status: 'MATCHED_AUDIT_RECORD',
        report_id: audit.audit_id,
        scan_id: audit.scan_id,
        audit_date: audit.audit_date,
        overall_score: audit.overall_score,
        overall_status: audit.overall_status,
        pass_count: audit.pass_count,
        review_count: audit.review_count,
        fail_count: audit.fail_count,
        fatal_failures_count: audit.fatal_failures_count,
        agency_name: audit.agency_name,
        auditor_name: audit.auditor_name,
        created_at: audit.created_at
      };
    }

    // Check organization domain boundary
    if (tele.organization_id !== orgId) {
      return {
        verified: false,
        match_status: 'UNAUTHORIZED_ORGANIZATION',
        message: 'Access Denied: Report belongs to a different organization domain.'
      };
    }

    return {
      verified: true,
      match_status: 'MATCHED_TELEMETRY_RECORD',
      scan_id: tele.scan_id,
      organization_id: tele.organization_id,
      user_id: tele.user_id,
      device_id: tele.device_id,
      completed_at: tele.completed_at,
      duration_ms: tele.duration_ms,
      overall_score: tele.overall_score,
      scan_status: tele.scan_status,
      files_processed: tele.files_processed,
      pass_count: tele.pass_count,
      review_count: tele.review_count,
      fail_count: tele.fail_count,
      evidence_not_found_count: tele.evidence_not_found_count,
      critical_count: tele.critical_count,
      high_count: tele.high_count,
      application_version: tele.application_version,
      engine_version: tele.engine_version,
      checklist_version: tele.checklist_version
    };
  }

  /**
   * Retrieves queue status statistics
   */
  public getQueueStatus(orgId?: string) {
    let pendingQuery = "SELECT COUNT(*) as count FROM telemetry_queue WHERE status = 'PENDING'";
    let syncedQuery = "SELECT COUNT(*) as count FROM telemetry_queue WHERE status = 'SYNCED'";
    let failedQuery = "SELECT COUNT(*) as count FROM telemetry_queue WHERE status = 'FAILED'";
    const params: any[] = [];

    if (orgId) {
      pendingQuery += " AND organization_id = ?";
      syncedQuery += " AND organization_id = ?";
      failedQuery += " AND organization_id = ?";
      params.push(orgId);
    }

    const pending = (this.db.prepare(pendingQuery).get(...params) as any)?.count || 0;
    const synced = (this.db.prepare(syncedQuery).get(...params) as any)?.count || 0;
    const failed = (this.db.prepare(failedQuery).get(...params) as any)?.count || 0;

    return {
      pending_count: pending,
      synced_count: synced,
      failed_count: failed,
      total_queued: pending + synced + failed
    };
  }
}
