import fs from 'node:fs';
import path from 'node:path';

export interface CloudStorageProvider {
  upload(localPath: string, cloudObjectName: string): Promise<boolean>;
  verify(cloudObjectName: string, expectedSHA256: string): Promise<boolean>;
  deleteRemote(cloudObjectName: string): Promise<boolean>;
  getMetadata(cloudObjectName: string): Promise<{ exists: boolean; sha256?: string; size?: number } | null>;
}

/**
 * Local simulated Google Cloud Storage Provider.
 * Stores objects safely in a local cloud_quarantine_bucket folder to allow offline 
 * testing of upload, checksum verification, remote delete, and strict local deletion flow.
 */
export class LocalCloudStorageProvider implements CloudStorageProvider {
  private bucketPath: string;

  constructor(bucketName: string = 'filesentinel-quarantine-bucket') {
    this.bucketPath = path.resolve('./storage_bucket', bucketName);
    if (!fs.existsSync(this.bucketPath)) {
      fs.mkdirSync(this.bucketPath, { recursive: true });
    }
  }

  async upload(localPath: string, cloudObjectName: string): Promise<boolean> {
    try {
      if (!fs.existsSync(localPath)) return false;
      const targetPath = path.join(this.bucketPath, cloudObjectName);
      fs.copyFileSync(localPath, targetPath);
      return fs.existsSync(targetPath);
    } catch (e) {
      console.error('[Cloud Storage Upload Error]:', e);
      return false;
    }
  }

  async verify(cloudObjectName: string, expectedSHA256: string): Promise<boolean> {
    try {
      const targetPath = path.join(this.bucketPath, cloudObjectName);
      if (!fs.existsSync(targetPath)) return false;

      const buffer = fs.readFileSync(targetPath);
      const crypto = await import('node:crypto');
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');

      return hash === expectedSHA256;
    } catch {
      return false;
    }
  }

  async deleteRemote(cloudObjectName: string): Promise<boolean> {
    try {
      const targetPath = path.join(this.bucketPath, cloudObjectName);
      if (fs.existsSync(targetPath)) {
        fs.unlinkSync(targetPath);
      }
      return true;
    } catch {
      return false;
    }
  }

  async getMetadata(cloudObjectName: string): Promise<{ exists: boolean; sha256?: string; size?: number } | null> {
    try {
      const targetPath = path.join(this.bucketPath, cloudObjectName);
      if (!fs.existsSync(targetPath)) return { exists: false };

      const stats = fs.statSync(targetPath);
      const buffer = fs.readFileSync(targetPath);
      const crypto = await import('node:crypto');
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');

      return {
        exists: true,
        sha256: hash,
        size: stats.size
      };
    } catch {
      return { exists: false };
    }
  }
}
