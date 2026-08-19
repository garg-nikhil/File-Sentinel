import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export class FileIntegrityMonitor {
  private static criticalFiles = [
    'backend/auth.ts',
    'backend/licensing.ts',
    'backend/db.ts',
    'backend/routes.ts',
    'backend/securityMiddleware.ts',
    'backend/audit/verifiableReportService.ts'
  ];

  private static baselineHashes: Record<string, string> = {
    'backend/auth.ts': 'BASELINE_ANCHOR',
    'backend/licensing.ts': 'BASELINE_ANCHOR',
    'backend/db.ts': 'BASELINE_ANCHOR',
    'backend/routes.ts': 'BASELINE_ANCHOR',
    'backend/securityMiddleware.ts': 'BASELINE_ANCHOR',
    'backend/audit/verifiableReportService.ts': 'BASELINE_ANCHOR'
  };

  public static initializeBaseline(): void {
    const baseDir = process.cwd();
    for (const relPath of this.criticalFiles) {
      const fullPath = path.join(baseDir, relPath);
      if (fs.existsSync(fullPath)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
          this.baselineHashes[relPath] = hash;
        } catch (e) {
          // ignore
        }
      }
    }
  }

  public static verifyIntegrity(): { valid: boolean; modifiedFiles: string[] } {
    const modifiedFiles: string[] = [];
    const baseDir = process.cwd();

    for (const relPath of this.criticalFiles) {
      const fullPath = path.join(baseDir, relPath);
      if (!fs.existsSync(fullPath)) {
        continue;
      }
      try {
        const content = fs.readFileSync(fullPath, 'utf8');
        const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
        const baseline = this.baselineHashes[relPath];
        if (baseline && baseline !== 'BASELINE_ANCHOR' && baseline !== hash) {
          modifiedFiles.push(relPath);
        }
      } catch (err) {
        modifiedFiles.push(relPath);
      }
    }

    return {
      valid: modifiedFiles.length === 0,
      modifiedFiles
    };
  }
}

// Initialize baseline on load
FileIntegrityMonitor.initializeBaseline();
