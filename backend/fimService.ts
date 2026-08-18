import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  SignedFimManifest,
  EMBEDDED_MANUFACTURER_MANIFEST,
  verifySignedFimManifest,
  signFimManifest,
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
  private static activeManifest: SignedFimManifest = EMBEDDED_MANUFACTURER_MANIFEST;
  private static trustedPublicKey: string = TRUSTED_FIM_PUBLIC_KEY;

  /**
   * Sets the active signed manufacturer manifest (e.g. during verified release upgrade or test harness)
   */
  public static setManifest(manifest: SignedFimManifest, customPublicKey?: string): void {
    this.activeManifest = manifest;
    if (customPublicKey) this.trustedPublicKey = customPublicKey;
  }

  /**
   * Resets manifest to original embedded manufacturer baseline
   */
  public static resetToEmbeddedManifest(): void {
    this.activeManifest = EMBEDDED_MANUFACTURER_MANIFEST;
    this.trustedPublicKey = TRUSTED_FIM_PUBLIC_KEY;
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

    // Check for external immutable release_manifest.json if present
    let manifestToVerify = this.activeManifest;
    const releaseManifestPath = path.join(baseDir, 'release_manifest.json');
    if (fs.existsSync(releaseManifestPath) && this.activeManifest === EMBEDDED_MANUFACTURER_MANIFEST) {
      try {
        const fileContent = fs.readFileSync(releaseManifestPath, 'utf8');
        const parsed = JSON.parse(fileContent) as SignedFimManifest;
        if (parsed && parsed.payload && parsed.signature) {
          manifestToVerify = parsed;
        }
      } catch (err: any) {
        console.error('[FIM SECURITY FATAL] Failed to parse release_manifest.json:', err.message);
      }
    }

    // 1. Verify that the baseline manifest itself is authentic and manufacturer-signed
    const isManifestAuthentic = verifySignedFimManifest(manifestToVerify, this.trustedPublicKey);
    if (!isManifestAuthentic) {
      console.error('[FIM SECURITY FATAL] Manufacturer FIM manifest signature verification failed! Quarantining system.');
      return {
        valid: false,
        quarantined: true,
        manifestTampered: true,
        modifiedFiles: Object.keys(manifestToVerify?.payload?.files || {}),
        missingFiles: [],
        verifiedAt
      };
    }

    const modifiedFiles: string[] = [];
    const missingFiles: string[] = [];
    const manifestFiles = manifestToVerify.payload.files;

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

