import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';

export interface ProtectedLicenseState {
  organizationId: string;
  licenseId: string;
  signedLeaseJson: string;
  machineFingerprint: string;
  maxSeenTimestampIso: string;
  lastTrustedTimestampIso: string;
  status: string;
  graceUntilIso: string;
  expiresAtIso: string;
  clockRollbackDetected: boolean;
  updatedAtIso: string;
  maxSeenVersion?: string;
  maxSeenIssuedAtIso?: string;
}

export class ProtectedLicenseStore {
  private storeFilePath: string;

  constructor(customPath?: string) {
    if (customPath) {
      this.storeFilePath = customPath;
    } else {
      // Windows %ProgramData% or %APPDATA% fallback
      const baseDir = process.env.PROGRAMDATA
        || process.env.APPDATA
        || path.join(process.cwd(), '.security');

      const secDir = path.join(baseDir, 'FileSentinel', 'security');
      if (!fs.existsSync(secDir)) {
        fs.mkdirSync(secDir, { recursive: true });
      }
      this.storeFilePath = path.join(secDir, 'lic_protected.dat');
    }
  }

  /**
   * Generate deterministic machine hardware fingerprint
   */
  public static getMachineFingerprint(): string {
    const hostname = os.hostname();
    const platform = os.platform();
    const arch = os.arch();
    const cpus = os.cpus().map(c => c.model).join(';');
    const mem = os.totalmem().toString();

    const raw = `MACHINE_FP_V1::${hostname}::${platform}::${arch}::${cpus}::${mem}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  /**
   * Generate machine-unique AES-256 key
   */
  private getMachineKey(): Buffer {
    const fp = ProtectedLicenseStore.getMachineFingerprint();
    return crypto.pbkdf2Sync(fp, 'FS-PROTECTED-SALT-2026', 10000, 32, 'sha256');
  }

  /**
   * Encrypt payload with AES-256-GCM
   */
  private encrypt(text: string): string {
    const key = this.getMachineKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${tag}:${encrypted}`;
  }

  /**
   * Decrypt payload with AES-256-GCM
   */
  private decrypt(encryptedData: string): string | null {
    try {
      const parts = encryptedData.split(':');
      if (parts.length !== 3) return null;
      const iv = Buffer.from(parts[0], 'hex');
      const tag = Buffer.from(parts[1], 'hex');
      const encryptedText = parts[2];

      const key = this.getMachineKey();
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch {
      return null;
    }
  }

  /**
   * Read protected license state from file
   */
  public loadState(): ProtectedLicenseState | null {
    if (!fs.existsSync(this.storeFilePath)) {
      return null;
    }

    try {
      const raw = fs.readFileSync(this.storeFilePath, 'utf8');
      const decrypted = this.decrypt(raw);
      if (!decrypted) return null;
      return JSON.parse(decrypted) as ProtectedLicenseState;
    } catch {
      return null;
    }
  }

  /**
   * Save protected license state to file
   */
  public saveState(state: ProtectedLicenseState): void {
    const json = JSON.stringify(state);
    const encrypted = this.encrypt(json);
    fs.writeFileSync(this.storeFilePath, encrypted, 'utf8');
  }
}
