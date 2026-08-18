import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  SignedFimManifest,
  verifySignedFimManifest,
  isValidManifestStructure,
  TRUSTED_FIM_PUBLIC_KEY
} from './fimManifest.js';

export interface FimVerificationResult {
  valid: boolean;
  quarantined: boolean;
  manifestTampered?: boolean;
  modifiedFiles: string[];
  missingFiles: string[];
  verifiedAt: string;
}

export class FileIntegrityMonitor {
  /**
   * Computes the SHA-256 hash of a file on disk
   */
  public static computeFileHash(filePath: string): string | null {
    if (!fs.existsSync(filePath)) return null;
    try {
      const content = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }

  /**
   * Verifies system files against the signed immutable release_manifest.json.
   * Fails closed if the manifest is missing, tampered, contains placeholder hashes,
   * fails signature verification, or if any protected file is modified, replaced, or missing.
   */
  public static verifyIntegrity(customBaseDir?: string): FimVerificationResult {
    const verifiedAt = new Date().toISOString();
    const baseDir = customBaseDir || process.cwd();
    const releaseManifestPath = path.join(baseDir, 'release_manifest.json');

    if (!fs.existsSync(releaseManifestPath)) {
      console.error('[FIM SECURITY FATAL] release_manifest.json is missing. System quarantined.');
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: [],
        missingFiles: ['release_manifest.json'],
        verifiedAt
      };
    }

    let manifest: SignedFimManifest;
    try {
      const fileContent = fs.readFileSync(releaseManifestPath, 'utf8');
      manifest = JSON.parse(fileContent) as SignedFimManifest;
    } catch (err: any) {
      console.error('[FIM SECURITY FATAL] Failed to parse release_manifest.json:', err.message);
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: [],
        missingFiles: [],
        verifiedAt
      };
    }

    // 1. Verify that the baseline manifest itself is structurally valid and manufacturer-signed
    if (!isValidManifestStructure(manifest)) {
      console.error('[FIM SECURITY FATAL] Manufacturer FIM manifest structure is invalid or contains placeholder hashes. Quarantining system.');
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: Object.keys(manifest?.payload?.files || {}),
        missingFiles: [],
        verifiedAt
      };
    }

    const isManifestAuthentic = verifySignedFimManifest(manifest, TRUSTED_FIM_PUBLIC_KEY);
    if (!isManifestAuthentic) {
      console.error('[FIM SECURITY FATAL] Manufacturer FIM manifest signature verification failed! Quarantining system.');
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: Object.keys(manifest?.payload?.files || {}),
        missingFiles: [],
        verifiedAt
      };
    }

    // 2. Verify all protected files against their expected SHA-256 hashes
    const modifiedFiles: string[] = [];
    const missingFiles: string[] = [];
    const manifestFiles = manifest.payload.files;

    for (const [relPath, expectedHash] of Object.entries(manifestFiles)) {
      const fullPath = path.join(baseDir, relPath);
      if (!fs.existsSync(fullPath)) {
        missingFiles.push(relPath);
        continue;
      }

      const actualHash = this.computeFileHash(fullPath);
      if (!actualHash || actualHash !== expectedHash) {
        modifiedFiles.push(relPath);
      }
    }

    const hasViolations = modifiedFiles.length > 0 || missingFiles.length > 0;
    return {
      valid: !hasViolations,
      quarantined: hasViolations,
      manifestTampered: false,
      modifiedFiles,
      missingFiles,
      verifiedAt
    };
  }
}
