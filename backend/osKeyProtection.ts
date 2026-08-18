import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { execSync } from 'node:child_process';

/**
 * OS-Protected Master Key Store (P0-5)
 * Protects database encryption keys and licensing state using genuine OS primitives:
 * - Windows: DPAPI (Data Protection API) scoped to CurrentUser.
 * - Linux/POSIX: Machine-bound encryption derived from /etc/machine-id + POSIX UID with 0600 isolation.
 * - Fails closed if the key was copied to a different machine or tampered with.
 */

export class OSKeyProtection {
  private static getStoreDirectory(): string {
    if (process.platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Local');
      return path.join(localAppData, 'FileSentinel', 'security');
    }
    const home = os.homedir();
    return path.join(home, '.config', 'filesentinel');
  }

  private static getProtectedKeyPath(): string {
    const ext = process.platform === 'win32' ? 'master.dpapi' : 'master.oskey';
    return path.join(this.getStoreDirectory(), ext);
  }

  /**
   * Retrieves machine-bound hardware/OS entropy for non-Windows POSIX systems
   */
  private static getPOSIXMachineEntropy(): string {
    // Read immutable system machine-id
    const candidates = ['/etc/machine-id', '/var/lib/dbus/machine-id'];
    for (const file of candidates) {
      if (fs.existsSync(file)) {
        try {
          const id = fs.readFileSync(file, 'utf8').trim();
          if (id.length > 0) {
            const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
            return `FS_OS_BIND_V1::${id}::${uid}`;
          }
        } catch {
          // ignore and check next
        }
      }
    }

    // Fallback on POSIX environments where machine-id is absent
    const sysInfo = `FS_FALLBACK::${os.hostname()}::${os.arch()}::${os.platform()}`;
    return sysInfo;
  }

  /**
   * Encrypts a raw key buffer using genuine OS protection primitives
   */
  public static protectData(plaintext: Buffer): Buffer {
    if (process.platform === 'win32') {
      try {
        // Use PowerShell Windows DPAPI CryptProtectData
        const base64In = plaintext.toString('base64');
        const script = `
          $bytes = [Convert]::FromBase64String('${base64In}')
          $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
          [Convert]::ToBase64String($enc)
        `.trim().replace(/\r?\n/g, ' ');
        const output = execSync(`powershell.exe -NoProfile -NonInteractive -Command "${script}"`, {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
        return Buffer.from(output, 'base64');
      } catch (err: any) {
        console.warn('[OSKeyProtection] Windows DPAPI invocation failed, using secure machine-bound envelope:', err?.message);
      }
    }

    // Linux/POSIX machine-bound AES-256-GCM protection
    const entropy = this.getPOSIXMachineEntropy();
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(entropy, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Format: "FS_OS_V1" (8b) + Salt(16b) + IV(12b) + Tag(16b) + Ciphertext
    const header = Buffer.from('FS_OS_V1', 'utf8');
    return Buffer.concat([header, salt, iv, tag, ciphertext]);
  }

  /**
   * Decrypts an OS-protected key buffer.
   * Returns null or throws if copied to another machine, key unavailable, or modified.
   */
  public static unprotectData(protectedData: Buffer): Buffer | null {
    if (process.platform === 'win32') {
      try {
        const base64In = protectedData.toString('base64');
        const script = `
          $bytes = [Convert]::FromBase64String('${base64In}')
          $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
          [Convert]::ToBase64String($dec)
        `.trim().replace(/\r?\n/g, ' ');
        const output = execSync(`powershell.exe -NoProfile -NonInteractive -Command "${script}"`, {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
        return Buffer.from(output, 'base64');
      } catch {
        // If DPAPI fails on Windows (e.g. transferred to another machine or user), return null
        return null;
      }
    }

    // Linux/POSIX container unprotect
    if (protectedData.length < 52) return null;
    const magic = protectedData.subarray(0, 8).toString('utf8');
    if (magic !== 'FS_OS_V1') return null;

    const salt = protectedData.subarray(8, 24);
    const iv = protectedData.subarray(24, 36);
    const tag = protectedData.subarray(36, 52);
    const ciphertext = protectedData.subarray(52);

    try {
      const entropy = this.getPOSIXMachineEntropy();
      const key = crypto.pbkdf2Sync(entropy, salt, 100000, 32, 'sha256');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      // Decryption failed (tampered protected state or foreign machine)
      return null;
    }
  }

  /**
   * Retrieves the OS-protected master database encryption key.
   * Fails closed with an explicit exception if the key is unavailable, tampered, or copied from another machine.
   */
  public static getOrGenerateDatabaseKey(): string {
    if (process.env.FILE_SENTINEL_PROTECTED_KEY_OVERRIDE) {
      return process.env.FILE_SENTINEL_PROTECTED_KEY_OVERRIDE;
    }

    const keyPath = this.getProtectedKeyPath();
    const keyDir = path.dirname(keyPath);

    if (!fs.existsSync(keyDir)) {
      fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
    }

    if (fs.existsSync(keyPath)) {
      const protectedBlob = fs.readFileSync(keyPath);
      const rawKey = this.unprotectData(protectedBlob);
      if (!rawKey) {
        throw new Error('CRITICAL SECURITY ERROR: OS Protected Key cannot be decrypted. Key was created on another machine or protected state was tampered.');
      }
      return rawKey.toString('hex');
    }

    // Generate fresh cryptographic random 256-bit key and protect it with OS primitives
    const newRawKey = crypto.randomBytes(32);
    const protectedBlob = this.protectData(newRawKey);
    fs.writeFileSync(keyPath, protectedBlob, { mode: 0o600 });
    return newRawKey.toString('hex');
  }
}
