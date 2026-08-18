import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  SignedFimManifest,
  EMBEDDED_MANUFACTURER_MANIFEST,
  verifySignedFimManifest,
  signFimManifest,
  MANUFACTURER_FIM_SIGNING_KEY
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
  private static activeManifest: SignedFimManifest = EMBEDDED_MANUFACTURER_MANIFEST;
  private static manufacturerKey: string = MANUFACTURER_FIM_SIGNING_KEY;

  /**
   * Sets the active signed manufacturer manifest (e.g. during verified release upgrade or test harness)
   */
  public static setManifest(manifest: SignedFimManifest, key?: string): void {
    this.activeManifest = manifest;
    if (key) this.manufacturerKey = key;
  }

  /**
   * Resets manifest to original embedded manufacturer baseline
   */
  public static resetToEmbeddedManifest(): void {
    this.activeManifest = EMBEDDED_MANUFACTURER_MANIFEST;
    this.manufacturerKey = MANUFACTURER_FIM_SIGNING_KEY;
  }

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
   * Verifies system files against the signed manufacturer manifest.
   * Fails closed if the manifest signature is invalid, or if any critical file is modified or missing.
   */
  public static verifyIntegrity(customBaseDir?: string): FimVerificationResult {
    const verifiedAt = new Date().toISOString();
    const baseDir = customBaseDir || process.cwd();

    // 1. Verify that the baseline manifest itself is authentic and manufacturer-signed
    const isManifestAuthentic = verifySignedFimManifest(this.activeManifest, this.manufacturerKey);
    if (!isManifestAuthentic) {
      console.error('[FIM SECURITY FATAL] Manufacturer FIM manifest signature verification failed! Quarantining system.');
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: Object.keys(this.activeManifest?.payload?.files || {}),
        missingFiles: [],
        verifiedAt
      };
    }

    const modifiedFiles: string[] = [];
    const missingFiles: string[] = [];
    const manifestFiles = this.activeManifest.payload.files;

    for (const [relPath, expectedHash] of Object.entries(manifestFiles)) {
      const fullPath = path.join(baseDir, relPath);
      if (!fs.existsSync(fullPath)) {
        missingFiles.push(relPath);
        continue;
      }

      const actualHash = this.computeFileHash(fullPath);
      if (!actualHash || (expectedHash !== 'EMBEDDED_ANCHOR' && actualHash !== expectedHash)) {
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
