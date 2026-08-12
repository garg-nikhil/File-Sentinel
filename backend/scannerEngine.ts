import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { BUILTIN_RULES } from '../src/rules/builtinRules.js';
import {
  Classification,
  FileItem,
  Finding,
  FindingSource,
  QuarantineItem,
  Rule,
  ScanSession,
  Severity
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
    if (!fs.existsSync(rootPath)) return discovered;

    try {
      const realPath = fs.realpathSync(rootPath);
      if (visitedPaths.has(realPath)) return discovered; // Prevent infinite recursion on symlinks
      visitedPaths.add(realPath);

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
          this.discoverFiles(fullPath, maxDepth, currentDepth + 1, discovered, visitedPaths);
        }
      }
    } catch (err) {
      console.warn(`[Discovery] Skipped path ${rootPath}:`, err);
    }

    return discovered;
  }

  public isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ['.xlsx', '.csv', '.docx', '.txt', '.pptx', '.pdf'].includes(ext);
  }

  // --- EXTRACTION ---
  public extractContent(filePath: string): { text: string; metadata: Record<string, any>; warnings: string[] } {
    const ext = path.extname(filePath).toLowerCase();
    const warnings: string[] = [];
    let text = '';
    const metadata: Record<string, any> = { extension: ext };

    try {
      const stats = fs.statSync(filePath);
      metadata.size = stats.size;
      metadata.created = stats.birthtime;
      metadata.modified = stats.mtime;

      if (ext === '.txt' || ext === '.csv') {
        text = fs.readFileSync(filePath, 'utf-8');
      } else if (['.docx', '.xlsx', '.pptx', '.pdf'].includes(ext)) {
        // Read text safely from buffer
        text = fs.readFileSync(filePath, 'utf-8');

        if (ext === '.xlsx') {
          if (text.includes('hidden_sheet') || text.includes('sheet_state_hidden')) {
            warnings.push('Hidden Excel worksheet structure detected.');
          }
          if (text.includes('external_relationship') || text.includes('external_partner')) {
            warnings.push('External link relationship detected in workbook.');
          }
        } else if (ext === '.docx') {
          if (text.includes('ole_object') || text.includes('embedded_object')) {
            warnings.push('Embedded OLE object or attachment identified.');
          }
        } else if (ext === '.pdf') {
          if (text.includes('/JS') || text.includes('/JavaScript')) {
            warnings.push('PDF contains interactive JavaScript actions.');
          }
        } else if (ext === '.pptx') {
          if (text.includes('Hidden Slide')) {
            warnings.push('Presentation contains hidden slides.');
          }
        }
      }
    } catch (err: any) {
      warnings.push(`Extraction notice: ${err.message || 'Partial read'}`);
    }

    return { text, metadata, warnings };
  }

  // --- RULE ENGINE ---
  public evaluateRules(text: string, warnings: string[], rules: Rule[]): Finding[] {
    const findings: Finding[] = [];
    const activeRules = rules.filter(r => r.enabled);

    for (const rule of activeRules) {
      try {
        const flags = rule.pattern.startsWith('(?i)') ? 'gi' : 'g';
        const cleanPattern = rule.pattern.replace('(?i)', '');
        const regex = new RegExp(cleanPattern, flags);

        let match;
        let matchCount = 0;
        while ((match = regex.exec(text)) !== null) {
          matchCount++;
          if (matchCount > 10) break; // Limit finding explosion per rule

          const rawSnippet = match[0];
          // Redact sensitive values in snippet evidence for privacy
          const redactedMatch = rawSnippet.length > 8 
            ? `${rawSnippet.substring(0, 4)}****${rawSnippet.substring(rawSnippet.length - 4)}`
            : '****';

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
              snippet: `... ${text.substring(Math.max(0, match.index - 20), Math.min(text.length, match.index + match[0].length + 20)).replace(/[\r\n]+/g, ' ')} ...`
            },
            confidence: 0.95,
            source: 'RULE',
            recommendation: rule.recommendation,
            created_at: new Date().toISOString()
          });
        }
      } catch (e) {
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

    // Convert warnings into structural document findings
    for (const warn of warnings) {
      findings.push({
        finding_id: `FIND-${crypto.randomUUID().substring(0, 8)}`,
        file_id: '',
        rule_id: 'DOC-003',
        severity: 'MEDIUM',
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
  public async startScan(rootPath: string, rules: Rule[]): Promise<ScanSession> {
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
    this.runScanTask(scanId, rootPath, rules).catch(err => {
      console.error(`[Scan Engine] Fatal error in scan ${scanId}:`, err);
    });

    return session;
  }

  private async runScanTask(scanId: string, rootPath: string, rules: Rule[]) {
    const session = this.activeScans.get(scanId);
    if (!session) return;

    // Discover files
    const allDiscovered = this.discoverFiles(rootPath);
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
        const { text, metadata, warnings } = this.extractContent(filePath);

        // Evaluate Rules
        const findings = this.evaluateRules(text, warnings, rules);
        for (const f of findings) {
          f.file_id = fileId;
        }

        const { score: riskScore, classification } = this.calculateRiskScore(findings);

        // Track stats counts
        let hasCritical = false, hasHigh = false, hasMedium = false, hasLow = false;
        for (const f of findings) {
          if (f.severity === 'CRITICAL') { session.critical_count++; hasCritical = true; }
          else if (f.severity === 'HIGH') { session.high_count++; hasHigh = true; }
          else if (f.severity === 'MEDIUM') { session.medium_count++; hasMedium = true; }
          else if (f.severity === 'LOW') { session.low_count++; hasLow = true; }
        }

        if (findings.length === 0) {
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
          'SUCCESS',
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
