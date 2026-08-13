import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { defaultRegistry } from './extractors/registry.js';
import { ExtractionResult } from './extractors/base.js';
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
    visitedPaths: Set<string> = new Set()
  ): string[] {
    if (currentDepth > maxDepth) return discovered;

    // Resolve & normalize path for security (FINDING-05)
    const resolvedPath = path.resolve(rootPath);
    const normalizedPath = path.normalize(resolvedPath);

    // Enforce BASE_ALLOWED_DIR restriction if configured
    const baseAllowed = process.env.BASE_ALLOWED_DIR ? path.resolve(process.env.BASE_ALLOWED_DIR) : null;
    if (baseAllowed) {
      const rel = path.relative(baseAllowed, normalizedPath);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        throw new Error(`Access denied: Requested path '${normalizedPath}' is outside the allowed directory '${baseAllowed}'`);
      }
    }

    if (!fs.existsSync(normalizedPath)) return discovered;

    try {
      const realPath = fs.realpathSync(normalizedPath);
      if (visitedPaths.has(realPath)) return discovered; // Prevent infinite recursion on symlinks
      visitedPaths.add(realPath);

      const stats = fs.statSync(normalizedPath);
      if (stats.isFile()) {
        if (this.isSupportedFile(normalizedPath)) {
          discovered.push(normalizedPath);
        }
      } else if (stats.isDirectory()) {
        const entries = fs.readdirSync(normalizedPath);
        for (const entry of entries) {
          // Ignore node_modules, .git, dist, build for speed & safety
          if (['node_modules', '.git', 'dist', 'build', '.cache', '.aistudio'].includes(entry)) continue;
          const fullPath = path.join(normalizedPath, entry);
          this.discoverFiles(fullPath, maxDepth, currentDepth + 1, discovered, visitedPaths);
        }
      }
    } catch (err: any) {
      if (err.message && err.message.startsWith('Access denied')) {
        throw err;
      }
      console.warn(`[Discovery] Skipped path ${normalizedPath}:`, err);
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
  public async startScan(rootPath: string, rules: Rule[], settings?: AppSettings): Promise<ScanSession> {
    const scanId = `SCAN-${crypto.randomUUID().substring(0, 8)}`;
    const startTime = new Date().toISOString();

    const session: ScanSession = {
      scan_id: scanId,
      root_path: rootPath,
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
        processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      scanId, rootPath, startTime, 'SCANNING', 0, 0,
      0, 0, 0, 0, 0, 0, 0
    );

    // Run scanning in background async loop so API returns immediately
    this.runScanTask(scanId, rootPath, rules, settings).catch(err => {
      console.error(`[Scan Engine] Fatal error in scan ${scanId}:`, err);
    });

    return session;
  }

  private async runScanTask(scanId: string, rootPath: string, rules: Rule[], settings?: AppSettings) {
    const session = this.activeScans.get(scanId);
    if (!session) return;

    const maxScanDepth = settings?.maxScanDepth ?? 10;
    const maxFileSizeMB = settings?.maxFileSizeMB ?? 50;

    // Discover files up to maxScanDepth
    const allDiscovered = this.discoverFiles(rootPath, maxScanDepth);
    session.total_files = allDiscovered.length;
    session.supported_files = allDiscovered.length;

    for (let i = 0; i < allDiscovered.length; i++) {
      if (this.scanAbortControllers.get(scanId)) {
        session.status = 'CANCELLED';
        break;
      }

      const filePath = allDiscovered[i];
      session.current_file = path.basename(filePath);

      try {
        const stats = fs.statSync(filePath);
        const sha256 = this.calculateSHA256(filePath);
        const fileId = `FILE-${crypto.randomUUID().substring(0, 8)}`;

        // Check if file size exceeds configured limit before processing
        if (stats.size > maxFileSizeMB * 1024 * 1024) {
          const fileStmt = this.db.prepare(`
            INSERT INTO files (
              file_id, scan_id, path, filename, extension, size, sha256,
              risk_score, classification, scan_status, created_at, modified_at,
              extracted_text_preview, metadata_json, warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'UNKNOWN', 'SKIPPED', ?, ?, '', ?, ?)
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
          continue;
        }

        // Safe Modular Extraction
        const extraction = await this.extractContent(filePath, maxFileSizeMB);
        const text = extraction.text || '';
        const metadata = extraction.metadata || {};
        const warnings = extraction.warnings || [];

        let scanStatus: 'SUCCESS' | 'ERROR' | 'SKIPPED' = 'SUCCESS';
        if (metadata.error) {
          scanStatus = 'ERROR';
          session.error_count++;
        }

        // Evaluate Rules on full extracted text
        const findings = this.evaluateRules(extraction, rules);
        for (const f of findings) {
          f.file_id = fileId;
        }

        const { score: riskScore, classification } = this.calculateRiskScore(findings);

        // Track stats counts
        for (const f of findings) {
          if (f.severity === 'CRITICAL') session.critical_count++;
          else if (f.severity === 'HIGH') session.high_count++;
          else if (f.severity === 'MEDIUM') session.medium_count++;
          else if (f.severity === 'LOW') session.low_count++;
        }

        if (findings.length === 0 && scanStatus === 'SUCCESS') {
          session.safe_count++;
        }

        // Insert File Record
        const fileStmt = this.db.prepare(`
          INSERT INTO files (
            file_id, scan_id, path, filename, extension, size, sha256,
            risk_score, classification, scan_status, created_at, modified_at,
            extracted_text_preview, metadata_json, warnings_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
          JSON.stringify(metadata),
          JSON.stringify(warnings)
        );

        // Insert Findings Records
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
      // Yield execution slightly for UI responsiveness
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    if (session.status !== 'CANCELLED') {
      session.status = 'COMPLETED';
    }
    session.end_time = new Date().toISOString();
    session.current_file = undefined;

    // Update scan summary in database
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
  }

  public getScanProgress(scanId: string): ScanSession | undefined {
    return this.activeScans.get(scanId);
  }
}
