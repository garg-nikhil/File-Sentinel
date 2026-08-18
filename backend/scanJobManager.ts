import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from './db.js';
import { WorkerPool, WorkerTask } from './workers/workerPool.js';
import { defaultRegistry } from './extractors/registry.js';
import { ExtractionResult } from './extractors/base.js';

export type ScanJobStatus =
  | 'DISCOVERED'
  | 'QUEUED'
  | 'PROCESSING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'FAILED';

export type ScanFileState =
  | 'DISCOVERED'
  | 'QUEUED'
  | 'PROCESSING'
  | 'COMPLETED'
  | 'REVIEW'
  | 'FAILED'
  | 'SKIPPED';

export interface ScanJobRecord {
  scan_id: string;
  org_id: string;
  endpoint_id: string;
  checklist_id: string;
  checklist_version?: string;
  source_count: number;
  sources: string[];
  total_files: number;
  processed_files: number;
  failed_files: number;
  skipped_files: number;
  review_files: number;
  status: ScanJobStatus;
  started_at: string;
  completed_at?: string | null;
  error_count: number;
  evidence_hash?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanFileRecord {
  id: string;
  scan_id: string;
  org_id: string;
  source_path: string;
  file_path: string;
  filename: string;
  extension: string;
  file_size: number;
  sha256?: string;
  file_type: 'DOCUMENT' | 'IMAGE_OCR' | 'ARCHIVE' | 'OTHER';
  state: ScanFileState;
  error_message?: string;
  processing_time_ms?: number;
  extracted_evidence_count?: number;
  ocr_status?: string;
  ocr_confidence?: number;
  created_at: string;
  updated_at: string;
}

export interface CreateScanJobParams {
  scanId?: string;
  orgId: string;
  endpointId: string;
  checklistId: string;
  checklistVersion?: string;
  sources: string[];
  maxFileSizeMB?: number;
  maxScanDepth?: number;
  maxConcurrentParsers?: number;
  maxConcurrentOCR?: number;
}

export class ScanJobManager {
  private db: DatabaseSync;
  private workerPool: WorkerPool;
  private activeJobs: Map<string, { abortController: AbortController; isRunning: boolean }> = new Map();

  constructor(db?: DatabaseSync, workerPool?: WorkerPool) {
    this.db = db || getDatabase();
    this.workerPool = workerPool || new WorkerPool({ maxConcurrentParsers: 4, maxConcurrentOCR: 2 });
    this.ensureTables();
  }

  private ensureTables(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS scan_jobs (
          scan_id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL,
          endpoint_id TEXT NOT NULL,
          checklist_id TEXT NOT NULL,
          checklist_version TEXT,
          source_count INTEGER DEFAULT 0,
          sources_json TEXT NOT NULL,
          total_files INTEGER DEFAULT 0,
          processed_files INTEGER DEFAULT 0,
          failed_files INTEGER DEFAULT 0,
          skipped_files INTEGER DEFAULT 0,
          review_files INTEGER DEFAULT 0,
          status TEXT NOT NULL,
          started_at TEXT NOT NULL,
          completed_at TEXT,
          error_count INTEGER DEFAULT 0,
          current_batch INTEGER DEFAULT 0,
          config_json TEXT,
          stats_json TEXT,
          evidence_hash TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY (org_id) REFERENCES organizations(org_id)
        );

        CREATE TABLE IF NOT EXISTS scan_files (
          id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL,
          org_id TEXT NOT NULL,
          source_path TEXT NOT NULL,
          file_path TEXT NOT NULL,
          filename TEXT NOT NULL,
          extension TEXT NOT NULL,
          file_size INTEGER NOT NULL,
          sha256 TEXT,
          file_type TEXT NOT NULL,
          state TEXT NOT NULL,
          error_message TEXT,
          retry_count INTEGER DEFAULT 0,
          processing_time_ms INTEGER DEFAULT 0,
          extracted_evidence_count INTEGER DEFAULT 0,
          evidence_ids_json TEXT,
          ocr_status TEXT,
          ocr_confidence REAL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY (scan_id) REFERENCES scan_jobs(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_scan_files_scan_state ON scan_files(scan_id, state);
        CREATE INDEX IF NOT EXISTS idx_scan_files_sha256 ON scan_files(scan_id, sha256);
      `);
    } catch {}
  }

  /**
   * Helper to calculate SHA256 file hash safely
   */
  public calculateSHA256(filePath: string): string {
    try {
      const buffer = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(buffer).digest('hex');
    } catch {
      return '';
    }
  }

  /**
   * Discover files across multiple roots recursively
   */
  public discoverSourceFiles(
    sources: string[],
    maxDepth: number = 10
  ): { discoveredPaths: { sourcePath: string; filePath: string }[]; totalDiscovered: number } {
    const discoveredPaths: { sourcePath: string; filePath: string }[] = [];
    const visited = new Set<string>();

    for (const source of sources) {
      if (!fs.existsSync(source)) continue;

      const walk = (currentPath: string, depth: number) => {
        if (depth > maxDepth) return;
        try {
          const lstat = fs.lstatSync(currentPath);
          if (lstat.isSymbolicLink()) return; // Symlink protection

          const real = fs.realpathSync(currentPath);
          if (visited.has(real)) return;
          visited.add(real);

          if (lstat.isDirectory()) {
            const entries = fs.readdirSync(currentPath);
            for (const entry of entries) {
              walk(path.join(currentPath, entry), depth + 1);
            }
          } else if (lstat.isFile()) {
            discoveredPaths.push({ sourcePath: source, filePath: currentPath });
          }
        } catch {}
      };

      walk(source, 0);
    }

    return {
      discoveredPaths,
      totalDiscovered: discoveredPaths.length
    };
  }

  /**
   * Create and initialize a new scan job
   */
  public createScanJob(params: CreateScanJobParams): ScanJobRecord {
    const scanId = params.scanId || `SCAN-${crypto.randomUUID().substring(0, 8).toUpperCase()}`;
    const now = new Date().toISOString();

    const { discoveredPaths, totalDiscovered } = this.discoverSourceFiles(
      params.sources,
      params.maxScanDepth || 10
    );

    const initialStatus: ScanJobStatus = totalDiscovered > 0 ? 'QUEUED' : 'DISCOVERED';

    this.db.prepare(`
      INSERT INTO scan_jobs (
        scan_id, org_id, endpoint_id, checklist_id, checklist_version,
        source_count, sources_json, total_files, processed_files, failed_files,
        skipped_files, review_files, status, started_at, completed_at,
        error_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?, NULL, 0, ?, ?)
    `).run(
      scanId,
      params.orgId,
      params.endpointId,
      params.checklistId,
      params.checklistVersion || '1.0.0',
      params.sources.length,
      JSON.stringify(params.sources),
      totalDiscovered,
      initialStatus,
      now,
      now,
      now
    );

    // Insert discovered files into scan_files table
    const insertFileStmt = this.db.prepare(`
      INSERT INTO scan_files (
        id, scan_id, org_id, source_path, file_path, filename, extension,
        file_size, sha256, file_type, state, error_message, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'QUEUED', NULL, ?, ?)
    `);

    for (const item of discoveredPaths) {
      const ext = path.extname(item.filePath).toLowerCase();
      const filename = path.basename(item.filePath);
      let size = 0;
      try {
        size = fs.statSync(item.filePath).size;
      } catch {}

      const isImage = ['.jpg', '.jpeg', '.png', '.webp', '.tiff', '.tif'].includes(ext);
      const isDoc = ['.pdf', '.docx', '.xlsx', '.pptx', '.csv', '.txt'].includes(ext);
      const fileType = isImage ? 'IMAGE_OCR' : isDoc ? 'DOCUMENT' : 'OTHER';

      const fileId = `SF-${crypto.randomUUID().substring(0, 8).toUpperCase()}`;
      insertFileStmt.run(
        fileId,
        scanId,
        params.orgId,
        item.sourcePath,
        item.filePath,
        filename,
        ext,
        size,
        null,
        fileType,
        now,
        now
      );
    }

    return this.getScanJob(scanId, params.orgId)!;
  }

  /**
   * Execute or resume a scan job with bounded workers
   */
  public async executeScanJob(
    scanId: string,
    orgId: string,
    onProgress?: (job: ScanJobRecord) => void
  ): Promise<ScanJobRecord> {
    const job = this.getScanJob(scanId, orgId);
    if (!job) {
      throw new Error(`Scan job '${scanId}' not found for organization '${orgId}'`);
    }

    const abortController = new AbortController();
    this.activeJobs.set(scanId, { abortController, isRunning: true });

    const now = new Date().toISOString();
    this.db.prepare(
      "UPDATE scan_jobs SET status = 'PROCESSING', updated_at = ? WHERE scan_id = ? AND org_id = ?"
    ).run(now, scanId, orgId);

    // Fetch pending files (QUEUED, DISCOVERED, PROCESSING) - skips already COMPLETED files
    const pendingFiles = this.db.prepare(`
      SELECT * FROM scan_files
      WHERE scan_id = ? AND org_id = ? AND state IN ('QUEUED', 'DISCOVERED', 'PROCESSING')
      ORDER BY id ASC
    `).all(scanId, orgId) as unknown as ScanFileRecord[];

    const shaHashes: string[] = [];

    // Bounded processing loop with worker pool
    for (const fileRecord of pendingFiles) {
      if (abortController.signal.aborted) {
        break;
      }

      // Mark processing in SQLite
      this.db.prepare(
        "UPDATE scan_files SET state = 'PROCESSING', updated_at = ? WHERE id = ?"
      ).run(new Date().toISOString(), fileRecord.id);

      const isImage = fileRecord.file_type === 'IMAGE_OCR';
      const task: WorkerTask = {
        id: fileRecord.id,
        type: isImage ? 'IMAGE_OCR' : 'DOCUMENT',
        filePath: fileRecord.file_path,
        maxFileSizeMB: 50
      };

      const result = await this.workerPool.runTask(task);
      const fileNow = new Date().toISOString();
      let sha256 = '';
      try {
        sha256 = this.calculateSHA256(fileRecord.file_path);
        if (sha256) shaHashes.push(sha256);
      } catch {}

      let finalState: ScanFileState = 'COMPLETED';
      let errorMsg: string | null = null;
      let ocrStatus = 'NONE';
      let ocrConfidence = 1.0;

      if (!result.success || result.extraction?.metadata?.error) {
        finalState = 'FAILED';
        errorMsg = result.error || (result.extraction?.warnings?.[0] ?? 'Extraction failure');
      } else if (result.extraction?.metadata?.is_ocr) {
        ocrStatus = (result.extraction.metadata.ocr_status as string) || 'SUCCESS';
        ocrConfidence = (result.extraction.metadata.ocr_confidence as number) || 0.8;
        if (ocrStatus === 'PARTIAL' || ocrStatus === 'TIMEOUT' || ocrConfidence < 0.75) {
          finalState = 'REVIEW';
        }
      }

      this.db.prepare(`
        UPDATE scan_files SET
          state = ?,
          sha256 = ?,
          error_message = ?,
          processing_time_ms = ?,
          ocr_status = ?,
          ocr_confidence = ?,
          updated_at = ?
        WHERE id = ?
      `).run(
        finalState,
        sha256 || null,
        errorMsg,
        result.processingTimeMs,
        ocrStatus,
        ocrConfidence,
        fileNow,
        fileRecord.id
      );

      // Continuously update scan job aggregates
      this.updateJobStats(scanId, orgId);

      if (onProgress) {
        const currentJob = this.getScanJob(scanId, orgId);
        if (currentJob) onProgress(currentJob);
      }
    }

    // Determine final status
    const isAborted = abortController.signal.aborted;
    const finalJob = this.getScanJob(scanId, orgId)!;
    const completedAt = isAborted ? null : new Date().toISOString();
    const finalStatus: ScanJobStatus = isAborted
      ? 'PAUSED'
      : finalJob.failed_files > 0 && finalJob.processed_files === 0
      ? 'FAILED'
      : 'COMPLETED';

    // Compute cumulative evidence hash
    const combinedHashes = shaHashes.sort().join('');
    const evidenceHash = `SHA256:${crypto.createHash('sha256').update(combinedHashes || scanId, 'utf8').digest('hex')}`;

    this.db.prepare(`
      UPDATE scan_jobs SET
        status = ?,
        completed_at = ?,
        evidence_hash = ?,
        updated_at = ?
      WHERE scan_id = ? AND org_id = ?
    `).run(finalStatus, completedAt, evidenceHash, new Date().toISOString(), scanId, orgId);

    this.activeJobs.delete(scanId);
    return this.getScanJob(scanId, orgId)!;
  }

  private updateJobStats(scanId: string, orgId: string): void {
    const stats = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN state = 'COMPLETED' THEN 1 ELSE 0 END) as completed_count,
        SUM(CASE WHEN state = 'REVIEW' THEN 1 ELSE 0 END) as review_count,
        SUM(CASE WHEN state = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
        SUM(CASE WHEN state = 'SKIPPED' THEN 1 ELSE 0 END) as skipped_count
      FROM scan_files
      WHERE scan_id = ? AND org_id = ?
    `).get(scanId, orgId) as any;

    const completed = stats?.completed_count || 0;
    const review = stats?.review_count || 0;
    const failed = stats?.failed_count || 0;
    const skipped = stats?.skipped_count || 0;
    const totalProcessed = completed + review + failed + skipped;

    this.db.prepare(`
      UPDATE scan_jobs SET
        processed_files = ?,
        failed_files = ?,
        review_files = ?,
        skipped_files = ?,
        error_count = ?,
        updated_at = ?
      WHERE scan_id = ? AND org_id = ?
    `).run(
      completed,
      failed,
      review,
      skipped,
      failed,
      new Date().toISOString(),
      scanId,
      orgId
    );
  }

  public pauseScanJob(scanId: string, orgId: string): boolean {
    const active = this.activeJobs.get(scanId);
    if (active) {
      active.abortController.abort();
      this.activeJobs.delete(scanId);
    }

    const res = this.db.prepare(
      "UPDATE scan_jobs SET status = 'PAUSED', updated_at = ? WHERE scan_id = ? AND org_id = ?"
    ).run(new Date().toISOString(), scanId, orgId);

    return res.changes > 0;
  }

  public cancelScanJob(scanId: string, orgId: string): boolean {
    const active = this.activeJobs.get(scanId);
    if (active) {
      active.abortController.abort();
      this.activeJobs.delete(scanId);
    }

    const res = this.db.prepare(
      "UPDATE scan_jobs SET status = 'CANCELLED', updated_at = ? WHERE scan_id = ? AND org_id = ?"
    ).run(new Date().toISOString(), scanId, orgId);

    return res.changes > 0;
  }

  public getScanJob(scanId: string, orgId: string): ScanJobRecord | null {
    const row = this.db.prepare(
      'SELECT * FROM scan_jobs WHERE scan_id = ? AND org_id = ?'
    ).get(scanId, orgId) as any;

    if (!row) return null;

    let sources: string[] = [];
    try {
      sources = JSON.parse(row.sources_json || '[]');
    } catch {}

    return {
      scan_id: row.scan_id,
      org_id: row.org_id,
      endpoint_id: row.endpoint_id,
      checklist_id: row.checklist_id,
      checklist_version: row.checklist_version,
      source_count: row.source_count,
      sources,
      total_files: row.total_files,
      processed_files: row.processed_files,
      failed_files: row.failed_files,
      skipped_files: row.skipped_files,
      review_files: row.review_files,
      status: row.status as ScanJobStatus,
      started_at: row.started_at,
      completed_at: row.completed_at,
      error_count: row.error_count,
      evidence_hash: row.evidence_hash,
      created_at: row.created_at,
      updated_at: row.updated_at
    };
  }

  public listScanFiles(
    scanId: string,
    orgId: string,
    options?: { state?: ScanFileState; limit?: number; offset?: number }
  ): { files: ScanFileRecord[]; total: number } {
    const limit = options?.limit || 50;
    const offset = options?.offset || 0;

    let query = 'SELECT * FROM scan_files WHERE scan_id = ? AND org_id = ?';
    const params: any[] = [scanId, orgId];

    if (options?.state) {
      query += ' AND state = ?';
      params.push(options.state);
    }

    query += ' ORDER BY id ASC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = this.db.prepare(query).all(...params) as any[];

    const countQuery = options?.state
      ? 'SELECT COUNT(*) as total FROM scan_files WHERE scan_id = ? AND org_id = ? AND state = ?'
      : 'SELECT COUNT(*) as total FROM scan_files WHERE scan_id = ? AND org_id = ?';
    const countParams = options?.state ? [scanId, orgId, options.state] : [scanId, orgId];
    const totalRow = this.db.prepare(countQuery).get(...countParams) as any;

    return {
      files: rows.map(r => ({
        id: r.id,
        scan_id: r.scan_id,
        org_id: r.org_id,
        source_path: r.source_path,
        file_path: r.file_path,
        filename: r.filename,
        extension: r.extension,
        file_size: r.file_size,
        sha256: r.sha256,
        file_type: r.file_type,
        state: r.state,
        error_message: r.error_message,
        processing_time_ms: r.processing_time_ms,
        extracted_evidence_count: r.extracted_evidence_count,
        ocr_status: r.ocr_status,
        ocr_confidence: r.ocr_confidence,
        created_at: r.created_at,
        updated_at: r.updated_at
      })),
      total: totalRow?.total || 0
    };
  }

  public listScanJobs(orgId: string, limit: number = 20): ScanJobRecord[] {
    const rows = this.db.prepare(
      'SELECT * FROM scan_jobs WHERE org_id = ? ORDER BY started_at DESC LIMIT ?'
    ).all(orgId, limit) as any[];

    return rows.map(row => {
      let sources: string[] = [];
      try {
        sources = JSON.parse(row.sources_json || '[]');
      } catch {}
      return {
        scan_id: row.scan_id,
        org_id: row.org_id,
        endpoint_id: row.endpoint_id,
        checklist_id: row.checklist_id,
        checklist_version: row.checklist_version,
        source_count: row.source_count,
        sources,
        total_files: row.total_files,
        processed_files: row.processed_files,
        failed_files: row.failed_files,
        skipped_files: row.skipped_files,
        review_files: row.review_files,
        status: row.status as ScanJobStatus,
        started_at: row.started_at,
        completed_at: row.completed_at,
        error_count: row.error_count,
        evidence_hash: row.evidence_hash,
        created_at: row.created_at,
        updated_at: row.updated_at
      };
    });
  }
}
