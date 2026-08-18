import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { defaultRegistry } from './extractors/registry.js';
import { ExtractionResult } from './extractors/base.js';
import { PilotService } from './pilotService.js';
import {
  AppSettings,
  Classification,
  Finding,
  Rule,
  ScanSession
} from '../src/types.js';

export class FileScannerEngine {
  private db: any;
  private activeScans: Map<string, ScanSession> = new Map();
  private scanAbortControllers: Map<string, boolean> = new Map();

  constructor(db: any) {
    this.db = db;
  }

  // --- HASHING ---
  public calculateSHA256(filePath: string): string {
    try {
      const buffer = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(buffer).digest('hex');
    } catch {
      return '';
    }
  }

  // --- DISCOVERY ---
  public discoverFiles(
    rootPath: string,
    maxDepth: number = 10,
    currentDepth: number = 0,
    discovered: string[] = [],
    visitedPaths: Set<string> = new Set(),
    rootRealPath?: string
  ): string[] {
    if (currentDepth > maxDepth) return discovered;

    try {
      if (!fs.existsSync(rootPath) && !fs.lstatSync(rootPath).isSymbolicLink()) return discovered;

      let baseRootReal = rootRealPath;
      if (!baseRootReal) {
        try {
          const lstats = fs.lstatSync(rootPath);
          if (lstats.isDirectory() && !lstats.isSymbolicLink()) {
            baseRootReal = fs.realpathSync(rootPath);
          } else {
            baseRootReal = fs.realpathSync(path.dirname(rootPath));
          }
        } catch {
          baseRootReal = fs.realpathSync(path.dirname(rootPath));
        }

        // Default project containment: baseRootReal must be contained within process.cwd() unless BASE_ALLOWED_DIR is set
        if (!process.env.BASE_ALLOWED_DIR) {
          try {
            const projectRootReal = fs.realpathSync(process.cwd());
            const relToProject = path.relative(projectRootReal, baseRootReal);
            const isOutsideProject = relToProject === '..' || relToProject.startsWith('..' + path.sep) || relToProject.startsWith('../') || relToProject.startsWith('..\\') || path.isAbsolute(relToProject);
            if (isOutsideProject) {
              return discovered;
            }
          } catch {}
        }
      }

      let realTarget: string;
      try {
        realTarget = fs.realpathSync(rootPath);
      } catch {
        return discovered;
      }

      // Containment check against baseRootReal
      const rel = path.relative(baseRootReal, realTarget);
      const isOutside = rel === '..' || rel.startsWith('..' + path.sep) || rel.startsWith('../') || rel.startsWith('..\\') || path.isAbsolute(rel);
      if (isOutside) {
        return discovered;
      }

      // Enforce BASE_ALLOWED_DIR restriction if configured
      const baseAllowed = process.env.BASE_ALLOWED_DIR ? process.env.BASE_ALLOWED_DIR : null;
      if (baseAllowed) {
        try {
          const baseAllowedReal = fs.realpathSync(baseAllowed);
          const allowedRel = path.relative(baseAllowedReal, realTarget);
          if (allowedRel === '..' || allowedRel.startsWith('..' + path.sep) || allowedRel.startsWith('../') || allowedRel.startsWith('..\\') || path.isAbsolute(allowedRel)) {
            throw new Error(`Access denied: Requested path '${rootPath}' is outside the allowed directory '${baseAllowed}'`);
          }
        } catch (err: any) {
          if (err.message && err.message.startsWith('Access denied')) {
            throw err;
          }
          throw new Error(`Access denied: Requested path '${rootPath}' is outside the allowed directory '${baseAllowed}'`);
        }
      }

      if (visitedPaths.has(realTarget)) return discovered;
      visitedPaths.add(realTarget);

      const stats = fs.statSync(rootPath);
      if (stats.isFile()) {
        if (this.isSupportedFile(rootPath)) {
          discovered.push(rootPath);
        }
      } else if (stats.isDirectory()) {
        const entries = fs.readdirSync(rootPath);
        for (const entry of entries) {
          // Ignore node_modules, .git, dist, build for speed & safety
          if (['node_modules', '.git', 'dist', 'build', '.cache', '.aistudio'].includes(entry)) continue;
          const fullPath = path.join(rootPath, entry);
          this.discoverFiles(fullPath, maxDepth, currentDepth + 1, discovered, visitedPaths, baseRootReal);
        }
      }
    } catch (err: any) {
      if (err.message && err.message.startsWith('Access denied')) {
        throw err;
      }
      console.warn(`[Discovery] Skipped path ${rootPath}:`, err);
    }

    return discovered;
  }

  public isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ['.xlsx', '.xlsm', '.csv', '.docx', '.docm', '.txt', '.pptx', '.pptm', '.pdf'].includes(ext);
  }

  // --- SAFE MODULAR EXTRACTION ---
  public async extractContent(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
    return defaultRegistry.extract(filePath, maxFileSizeMB);
  }

  // --- RULE ENGINE ---
  public evaluateRules(extracted: ExtractionResult, rules: Rule[]): Finding[] {
    const findings: Finding[] = [];
    const activeRules = rules.filter(r => r.enabled);
    const text = extracted.text || '';
    const warnings = extracted.warnings || [];

    for (const rule of activeRules) {
      try {
        const flags = rule.pattern.startsWith('(?i)') ? 'gi' : 'g';
        const cleanPattern = rule.pattern.replace('(?i)', '');
        const regex = new RegExp(cleanPattern, flags);

        let match;
        let matchCount = 0;
        while ((match = regex.exec(text)) !== null) {
          matchCount++;
          if (matchCount > 15) break; // Limit finding explosion per rule

          const rawSnippet = match[0];
          const redactedMatch = this.redactEvidence(rawSnippet, rule.category);

          // Build snippet context
          const start = Math.max(0, match.index - 30);
          const end = Math.min(text.length, match.index + match[0].length + 30);
          const snippetText = text.substring(start, end).replace(/[\r\n]+/g, ' ');

          findings.push({
            finding_id: `FIND-${crypto.randomUUID().substring(0, 8)}`,
            file_id: '',
            rule_id: rule.id,
            severity: rule.severity,
            category: rule.category,
            title: rule.name,
            description: rule.description,
            evidence: {
              match: redactedMatch,
              snippet: `... ${this.redactEvidence(snippetText, rule.category)} ...`
            },
            confidence: 0.95,
            source: 'RULE',
            recommendation: rule.recommendation,
            created_at: new Date().toISOString()
          });
        }
      } catch {
        // Fallback for simple includes if regex failed
        if (text.toLowerCase().includes(rule.name.toLowerCase())) {
          findings.push({
            finding_id: `FIND-${crypto.randomUUID().substring(0, 8)}`,
            file_id: '',
            rule_id: rule.id,
            severity: rule.severity,
            category: rule.category,
            title: rule.name,
            description: rule.description,
            evidence: { snippet: `Keyword trigger match: ${rule.name}` },
            confidence: 0.7,
            source: 'HEURISTIC',
            recommendation: rule.recommendation,
            created_at: new Date().toISOString()
          });
        }
      }
    }

    // Convert structural document warnings into findings
    for (const warn of warnings) {
      if (warn.includes('exceeds configured limit')) continue; // Handled at file scan status level

      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
      if (warn.includes('VBA Macro') || warn.includes('JavaScript') || warn.includes('Launch')) {
        severity = 'HIGH';
      }

      findings.push({
        finding_id: `FIND-${crypto.randomUUID().substring(0, 8)}`,
        file_id: '',
        rule_id: 'DOC-003',
        severity,
        category: 'DOCUMENT',
        title: 'Potentially Risky Document Feature',
        description: warn,
        evidence: { snippet: warn },
        confidence: 0.9,
        source: 'HEURISTIC',
        recommendation: 'Inspect document structural features and confirm safety.',
        created_at: new Date().toISOString()
      });
    }

    return findings;
  }

  public redactEvidence(matchStr: string, category: string): string {
    if (!matchStr || matchStr.length <= 2) return '****';

    // Key-value pair redaction e.g., password=Secret123 -> password=Se****23
    const kvMatch = matchStr.match(/^([^:=]+[:=]\s*)(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1];
      const val = kvMatch[2];
      const redactedVal = val.length > 6 ? `${val.substring(0, 2)}****${val.substring(val.length - 2)}` : '****';
      return `${key}${redactedVal}`;
    }

    // Email redaction
    if (matchStr.includes('@')) {
      const parts = matchStr.split('@');
      const user = parts[0];
      const domain = parts[1] || '';
      const redUser = user.length > 2 ? `${user[0]}****${user[user.length - 1]}` : '*';
      return `${redUser}@${domain}`;
    }

    if (category === 'SECRETS') {
      return matchStr.length > 8
        ? `${matchStr.substring(0, 3)}****${matchStr.substring(matchStr.length - 3)}`
        : '****';
    }

    return matchStr.length > 10
      ? `${matchStr.substring(0, 4)}****${matchStr.substring(matchStr.length - 4)}`
      : '****';
  }

  // --- RISK SCORING & CLASSIFICATION ---
  public calculateRiskScore(findings: Finding[]): { score: number; classification: Classification } {
    if (findings.length === 0) {
      return { score: 0, classification: 'PUBLIC' };
    }

    let baseScore = 0;
    let criticals = 0;
    let highs = 0;
    let mediums = 0;
    let lows = 0;

    for (const f of findings) {
      if (f.severity === 'CRITICAL') criticals++;
      else if (f.severity === 'HIGH') highs++;
      else if (f.severity === 'MEDIUM') mediums++;
      else if (f.severity === 'LOW') lows++;
    }

    // Weighted non-linear calculation with capping to prevent single finding inflation
    baseScore += Math.min(criticals * 40, 80);
    baseScore += Math.min(highs * 25, 50);
    baseScore += Math.min(mediums * 10, 30);
    baseScore += Math.min(lows * 5, 15);

    const finalScore = Math.min(100, Math.max(0, baseScore));

    let classification: Classification = 'INTERNAL';
    if (finalScore >= 80) classification = 'RESTRICTED';
    else if (finalScore >= 50) classification = 'CONFIDENTIAL';
    else if (finalScore >= 20) classification = 'INTERNAL';
    else classification = 'PUBLIC';

    return { score: finalScore, classification };
  }

  // --- SCAN ORCHESTRATION ---
  public async startScan(rootPaths: string | string[], rules: Rule[], settings?: AppSettings, orgId?: string, userId?: string, deviceId?: string): Promise<ScanSession> {
    const pathsArray = Array.isArray(rootPaths) ? rootPaths : [rootPaths];
    const rootPathStr = pathsArray.join(', ');
    const scanId = `SCAN-${crypto.randomUUID()}`;
    const startTime = new Date().toISOString();

    const session: ScanSession = {
      scan_id: scanId,
      root_path: rootPathStr,
      start_time: startTime,
      status: 'SCANNING',
      total_files: 0,
      supported_files: 0,
      processed_files: 0,
      error_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      safe_count: 0,
      current_file: 'Discovering files...'
    };

    this.activeScans.set(scanId, session);
    this.scanAbortControllers.set(scanId, false);

    // Save scan entry in sqlite
    const stmt = this.db.prepare(`
      INSERT INTO scans (
        scan_id, root_path, start_time, status, total_files, supported_files,
        processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count,
        org_id, user_id, device_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      scanId, rootPathStr, startTime, 'SCANNING', 0, 0,
      0, 0, 0, 0, 0, 0, 0,
      orgId || null, userId || null, deviceId || null
    );

    // Run scanning in background async loop so API returns immediately
    this.runScanTask(scanId, pathsArray, rules, settings, orgId, userId, deviceId).catch(err => {
      console.error(`[Scan Engine] Fatal error in scan ${scanId}:`, err);
    });

    return session;
  }

  public pauseScan(scanId: string): boolean {
    this.scanAbortControllers.set(scanId, true);
    const session = this.activeScans.get(scanId);
    if (session) {
      session.status = 'PAUSED';
      session.current_file = undefined;
    }
    this.db.prepare("UPDATE scans SET status = 'PAUSED' WHERE scan_id = ?").run(scanId);
    return true;
  }

  public async resumeScan(
    scanId: string,
    rules: Rule[],
    settings?: AppSettings,
    orgId?: string,
    userId?: string,
    deviceId?: string
  ): Promise<ScanSession> {
    const scanRow = this.db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;
    if (!scanRow) {
      throw new Error(`Scan session '${scanId}' not found`);
    }

    const pathsArray = scanRow.root_path ? scanRow.root_path.split(', ') : [];
    
    // Fetch already processed files from database for this scan_id
    const completedRows = this.db.prepare(
      "SELECT path FROM files WHERE scan_id = ? AND scan_status IN ('SUCCESS', 'ERROR', 'SKIPPED')"
    ).all(scanId) as any[];
    const completedPaths = new Set<string>(completedRows.map(r => r.path));

    const session: ScanSession = {
      scan_id: scanId,
      root_path: scanRow.root_path,
      start_time: scanRow.start_time,
      status: 'SCANNING',
      total_files: scanRow.total_files || 0,
      supported_files: scanRow.supported_files || 0,
      processed_files: scanRow.processed_files || completedPaths.size,
      error_count: scanRow.error_count || 0,
      critical_count: scanRow.critical_count || 0,
      high_count: scanRow.high_count || 0,
      medium_count: scanRow.medium_count || 0,
      low_count: scanRow.low_count || 0,
      safe_count: scanRow.safe_count || 0,
      current_file: 'Resuming scan...'
    };

    this.activeScans.set(scanId, session);
    this.scanAbortControllers.set(scanId, false);

    this.db.prepare("UPDATE scans SET status = 'SCANNING' WHERE scan_id = ?").run(scanId);

    // Run resume background task
    this.runResumeScanTask(scanId, pathsArray, completedPaths, rules, settings, orgId, userId, deviceId).catch(err => {
      console.error(`[Scan Engine] Fatal error in resumed scan ${scanId}:`, err);
    });

    return session;
  }

  private async runScanTask(
    scanId: string,
    pathsArray: string[],
    rules: Rule[],
    settings?: AppSettings,
    orgId?: string,
    userId?: string,
    deviceId?: string
  ) {
    const session = this.activeScans.get(scanId);
    if (!session) return;

    const maxScanDepth = settings?.maxScanDepth ?? 10;
    const { RESOURCE_LIMITS } = await import('./resourceLimits.js');

    const allDiscovered: string[] = [];
    for (const rp of pathsArray) {
      if (!rp || !rp.trim()) continue;
      const discovered = this.discoverFiles(rp.trim(), maxScanDepth);
      for (const d of discovered) {
        if (!allDiscovered.includes(d)) {
          allDiscovered.push(d);
        }
      }
    }
    session.total_files = allDiscovered.length;
    session.supported_files = allDiscovered.length;

    let filesToProcess = allDiscovered;
    if (allDiscovered.length > RESOURCE_LIMITS.maxBatchFiles) {
      session.status = 'SCAN_LIMIT_EXCEEDED';
      filesToProcess = allDiscovered.slice(0, RESOURCE_LIMITS.maxBatchFiles);
    }

    await this.processFileQueue(scanId, filesToProcess, rules, settings, orgId, userId, deviceId);
  }

  private async runResumeScanTask(
    scanId: string,
    pathsArray: string[],
    completedPaths: Set<string>,
    rules: Rule[],
    settings?: AppSettings,
    orgId?: string,
    userId?: string,
    deviceId?: string
  ) {
    const session = this.activeScans.get(scanId);
    if (!session) return;

    const maxScanDepth = settings?.maxScanDepth ?? 10;
    const { RESOURCE_LIMITS } = await import('./resourceLimits.js');

    const allDiscovered: string[] = [];
    for (const rp of pathsArray) {
      if (!rp || !rp.trim()) continue;
      const discovered = this.discoverFiles(rp.trim(), maxScanDepth);
      for (const d of discovered) {
        if (!allDiscovered.includes(d)) {
          allDiscovered.push(d);
        }
      }
    }

    session.total_files = Math.max(session.total_files, allDiscovered.length);
    session.supported_files = session.total_files;

    const remainingFiles = allDiscovered.filter(fp => !completedPaths.has(fp));

    if (remainingFiles.length === 0) {
      session.status = 'COMPLETED';
      session.end_time = new Date().toISOString();
      session.current_file = undefined;
      this.db.prepare("UPDATE scans SET status = 'COMPLETED', end_time = ? WHERE scan_id = ?").run(session.end_time, scanId);
      return;
    }

    let filesToProcess = remainingFiles;
    if (filesToProcess.length > RESOURCE_LIMITS.maxBatchFiles) {
      session.status = 'SCAN_LIMIT_EXCEEDED';
      filesToProcess = filesToProcess.slice(0, RESOURCE_LIMITS.maxBatchFiles);
    }

    await this.processFileQueue(scanId, filesToProcess, rules, settings, orgId, userId, deviceId);
  }

  private async processFileQueue(
    scanId: string,
    filesToProcess: string[],
    rules: Rule[],
    settings?: AppSettings,
    orgId?: string,
    userId?: string,
    deviceId?: string
  ) {
    const session = this.activeScans.get(scanId);
    if (!session) return;

    const maxFileSizeMB = settings?.maxFileSizeMB ?? 50;
    const { RESOURCE_LIMITS, withTimeout } = await import('./resourceLimits.js');
    const concurrency = RESOURCE_LIMITS.maxConcurrentParsers;

    // Record PENDING files in DB upfront for tracking
    const checkStmt = this.db.prepare('SELECT file_id FROM files WHERE scan_id = ? AND path = ?');
    const insertPendingStmt = this.db.prepare(`
      INSERT INTO files (
        file_id, scan_id, path, filename, extension, size, sha256,
        risk_score, classification, scan_status, created_at, modified_at,
        extracted_text_preview, extracted_text, metadata_json, warnings_json
      ) VALUES (?, ?, ?, ?, ?, 0, '', 0, 'UNKNOWN', 'PENDING', ?, ?, '', '', '{}', '[]')
    `);

    for (const filePath of filesToProcess) {
      const existing = checkStmt.get(scanId, filePath);
      if (!existing) {
        const fileId = `FILE-${crypto.randomUUID().substring(0, 8)}`;
        const now = new Date().toISOString();
        try {
          insertPendingStmt.run(
            fileId,
            scanId,
            filePath,
            path.basename(filePath),
            path.extname(filePath).toLowerCase(),
            now,
            now
          );
        } catch (e) {}
      }
    }

    for (let chunkIdx = 0; chunkIdx < filesToProcess.length; chunkIdx += concurrency) {
      if (this.scanAbortControllers.get(scanId)) {
        session.status = 'PAUSED';
        session.current_file = undefined;
        this.db.prepare(`
          UPDATE scans SET
            status = 'PAUSED', processed_files = ?, error_count = ?,
            critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, safe_count = ?
          WHERE scan_id = ?
        `).run(
          session.processed_files, session.error_count, session.critical_count,
          session.high_count, session.medium_count, session.low_count, session.safe_count, scanId
        );
        return;
      }

      const chunk = filesToProcess.slice(chunkIdx, chunkIdx + concurrency);

      await Promise.all(chunk.map(async (filePath) => {
        session.current_file = path.basename(filePath);

        try {
          this.db.prepare("UPDATE files SET scan_status = 'PROCESSING' WHERE scan_id = ? AND path = ? AND scan_status = 'PENDING'").run(scanId, filePath);
        } catch (e) {}

        try {
          const stats = fs.statSync(filePath);
          const sha256 = this.calculateSHA256(filePath);
          const fileRow = this.db.prepare('SELECT file_id FROM files WHERE scan_id = ? AND path = ?').get(scanId, filePath) as any;
          const fileId = fileRow?.file_id || `FILE-${crypto.randomUUID().substring(0, 8)}`;

          if (stats.size > maxFileSizeMB * 1024 * 1024) {
            const fileStmt = this.db.prepare(`
              INSERT OR REPLACE INTO files (
                file_id, scan_id, path, filename, extension, size, sha256,
                risk_score, classification, scan_status, created_at, modified_at,
                extracted_text_preview, extracted_text, metadata_json, warnings_json
              ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'UNKNOWN', 'SKIPPED', ?, ?, '', '', ?, ?)
            `);
            fileStmt.run(
              fileId,
              scanId,
              filePath,
              path.basename(filePath),
              path.extname(filePath).toLowerCase(),
              stats.size,
              sha256,
              stats.birthtime.toISOString(),
              stats.mtime.toISOString(),
              JSON.stringify({ extension: path.extname(filePath).toLowerCase(), size: stats.size, skipped: true }),
              JSON.stringify([`File exceeds configured maximum scan size (${maxFileSizeMB} MB)`])
            );

            session.processed_files++;
            return;
          }

          let extraction: ExtractionResult;
          let scanStatus: 'SUCCESS' | 'ERROR' | 'SKIPPED' = 'SUCCESS';

          try {
            extraction = await withTimeout(this.extractContent(filePath, maxFileSizeMB), RESOURCE_LIMITS.processingTimeoutMs);
          } catch (timeoutErr: any) {
            const isTimeout = timeoutErr.code === 'PROCESSING_TIMEOUT' || (timeoutErr.message && timeoutErr.message.includes('PROCESSING_TIMEOUT'));
            const statusMsg = isTimeout ? 'PROCESSING_TIMEOUT' : 'EXTRACTION_ERROR';
            extraction = {
              text: '',
              metadata: { extension: path.extname(filePath), size: stats.size, error: true, [statusMsg.toLowerCase()]: true },
              links: [],
              embeddedObjects: [],
              structure: {},
              warnings: [timeoutErr.message || 'Processing timeout or fatal error']
            };
            scanStatus = 'ERROR';
            session.error_count++;
          }

          const text = extraction.text || '';
          const metadata = extraction.metadata || {};
          const warnings = extraction.warnings || [];

          if (metadata.error || metadata.resourceLimitExceeded || metadata.processing_timeout) {
            scanStatus = 'ERROR';
            session.error_count++;
          }

          const findings = this.evaluateRules(extraction, rules);
          for (const f of findings) {
            f.file_id = fileId;
          }

          let { score: riskScore, classification } = this.calculateRiskScore(findings);

          if (metadata.truncated || metadata.resourceLimitExceeded || warnings.some(w => w.includes('RESOURCE_LIMIT_EXCEEDED'))) {
            if (classification === 'PUBLIC') {
              classification = 'CONFIDENTIAL';
              riskScore = Math.max(riskScore, 50);
            }
          }

          for (const f of findings) {
            if (f.severity === 'CRITICAL') session.critical_count++;
            else if (f.severity === 'HIGH') session.high_count++;
            else if (f.severity === 'MEDIUM') session.medium_count++;
            else if (f.severity === 'LOW') session.low_count++;
          }

          if (findings.length === 0 && scanStatus === 'SUCCESS') {
            session.safe_count++;
          }

          const fileStmt = this.db.prepare(`
            INSERT OR REPLACE INTO files (
              file_id, scan_id, path, filename, extension, size, sha256,
              risk_score, classification, scan_status, created_at, modified_at,
              extracted_text_preview, extracted_text, metadata_json, warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          fileStmt.run(
            fileId,
            scanId,
            filePath,
            path.basename(filePath),
            path.extname(filePath).toLowerCase(),
            stats.size,
            sha256,
            riskScore,
            classification,
            scanStatus,
            stats.birthtime.toISOString(),
            stats.mtime.toISOString(),
            text.substring(0, 500),
            text,
            JSON.stringify(metadata),
            JSON.stringify(warnings)
          );

          const findingStmt = this.db.prepare(`
            INSERT INTO findings (
              finding_id, file_id, rule_id, severity, category, title,
              description, evidence_json, confidence, source, recommendation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);

          for (const f of findings) {
            findingStmt.run(
              f.finding_id,
              fileId,
              f.rule_id,
              f.severity,
              f.category,
              f.title,
              f.description,
              JSON.stringify(f.evidence),
              f.confidence,
              f.source,
              f.recommendation,
              f.created_at
            );
          }

        } catch (err: any) {
          session.error_count++;
          console.error(`Error scanning file ${filePath}:`, err);
        }

        session.processed_files++;
      }));

      // Update SQLite scan progress after chunk
      this.db.prepare(`
        UPDATE scans SET
          total_files = ?, processed_files = ?, error_count = ?, critical_count = ?,
          high_count = ?, medium_count = ?, low_count = ?, safe_count = ?
        WHERE scan_id = ?
      `).run(
        session.total_files, session.processed_files, session.error_count,
        session.critical_count, session.high_count, session.medium_count,
        session.low_count, session.safe_count, scanId
      );
    }

    if (this.scanAbortControllers.get(scanId)) {
      session.status = 'PAUSED';
      session.current_file = undefined;
      this.db.prepare("UPDATE scans SET status = 'PAUSED' WHERE scan_id = ?").run(scanId);
      return;
    }

    if (session.status !== 'CANCELLED' && session.status !== 'SCAN_LIMIT_EXCEEDED' && session.status !== 'PAUSED') {
      try {
        session.current_file = 'Evaluating compliance...';
        const { EvidenceEngine } = await import('./audit/evidenceEngine.js');
        const evidenceEngine = new EvidenceEngine(this.db);
        const resolvedOrgId = orgId || (this.db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(scanId) as any)?.org_id || 'default_org';
        await evidenceEngine.runAuditScanForSession({
          scanId,
          orgId: resolvedOrgId
        });
      } catch(err) {
        console.error(`[Scan Engine] Audit evaluation failed for scan ${scanId}:`, err);
      } finally {
        session.current_file = undefined;
      }
      session.status = 'COMPLETED';
    }
    session.end_time = new Date().toISOString();
    session.current_file = undefined;

    const updateStmt = this.db.prepare(`
      UPDATE scans SET
        status = ?, end_time = ?, total_files = ?, supported_files = ?,
        processed_files = ?, error_count = ?, critical_count = ?, high_count = ?,
        medium_count = ?, low_count = ?, safe_count = ?
      WHERE scan_id = ?
    `);
    updateStmt.run(
      session.status,
      session.end_time,
      session.total_files,
      session.supported_files,
      session.processed_files,
      session.error_count,
      session.critical_count,
      session.high_count,
      session.medium_count,
      session.low_count,
      session.safe_count,
      scanId
    );

    try {
      const pilotService = new PilotService(this.db);
      const targetOrgId = orgId || 'org-default';
      const targetUserId = userId || 'user-default';
      const targetDeviceId = deviceId || 'dev-default';
      const completedCount = (this.db.prepare("SELECT COUNT(*) as count FROM scans WHERE org_id = ? AND status = 'COMPLETED'").get(targetOrgId) as any)?.count || 0;
      if (session.status === 'COMPLETED') {
        pilotService.recordTelemetry('completed_scan', targetOrgId, targetUserId, targetDeviceId, { scan_id: scanId, total_files: session.total_files });
        if (completedCount === 1) {
          pilotService.recordTelemetry('first_scan', targetOrgId, targetUserId, targetDeviceId, { scan_id: scanId });
        } else if (completedCount === 2) {
          pilotService.recordTelemetry('second_scan', targetOrgId, targetUserId, targetDeviceId, { scan_id: scanId });
        }
      } else {
        pilotService.recordTelemetry('failed_scan', targetOrgId, targetUserId, targetDeviceId, { scan_id: scanId, status: session.status });
      }
    } catch (e) {
      console.warn('[ScannerEngine] Pilot telemetry error:', e);
    }

    // 3. Privacy-Preserving Telemetry Generation & Offline Queueing
    if (settings?.telemetryEnabled !== false) {
      try {
        const { TelemetryService } = await import('./telemetry.js');
        const telemetryService = new TelemetryService(this.db);
        const telemetryPayload = telemetryService.buildTelemetryPayload(
          scanId,
          orgId || 'org-default',
          userId || 'user-default',
          deviceId || 'dev-default',
          {
            debugFilenamesEnabled: Boolean(settings?.debugFilenamesEnabled),
            applicationVersion: '1.0.0',
            engineVersion: '1.0.0',
            checklistVersion: '2026.1'
          }
        );
        if (telemetryPayload) {
          telemetryService.enqueue(telemetryPayload);
          telemetryService.flushQueue();
        }
      } catch (telemetryErr) {
        // NON-BLOCKING INVARIANT: Telemetry failure must NEVER fail the local scan or audit results.
        console.warn('[Telemetry] Non-blocking telemetry capture notice:', telemetryErr);
      }
    }
  }

  public getScanProgress(scanId: string): ScanSession | undefined {
    const active = this.activeScans.get(scanId);
    if (active) return active;

    const row = this.db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;
    if (!row) return undefined;

    return {
      scan_id: row.scan_id,
      root_path: row.root_path,
      start_time: row.start_time,
      end_time: row.end_time || undefined,
      status: row.status as any,
      total_files: row.total_files || 0,
      supported_files: row.supported_files || 0,
      processed_files: row.processed_files || 0,
      error_count: row.error_count || 0,
      critical_count: row.critical_count || 0,
      high_count: row.high_count || 0,
      medium_count: row.medium_count || 0,
      low_count: row.low_count || 0,
      safe_count: row.safe_count || 0,
      current_file: row.status === 'SCANNING' ? 'Processing...' : undefined
    };
  }
}
