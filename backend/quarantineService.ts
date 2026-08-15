import fs from 'node:fs';
import path from 'node:path';
import { Storage } from '@google-cloud/storage';

export interface CloudStorageProvider {
  upload(localPath: string, cloudObjectName: string): Promise<boolean>;
  verify(cloudObjectName: string, expectedSHA256: string, expectedSize: number): Promise<boolean>;
  deleteRemote(cloudObjectName: string): Promise<boolean>;
  getMetadata(cloudObjectName: string): Promise<{ exists: boolean; sha256?: string; size?: number } | null>;
}

/**
 * Real Google Cloud Storage Provider using official @google-cloud/storage SDK
 */
export class GoogleCloudStorageProvider implements CloudStorageProvider {
  private storage: Storage;
  private bucketName: string;

  constructor(bucketName?: string) {
    this.bucketName = bucketName || process.env.GOOGLE_CLOUD_BUCKET || 'filesentinel-quarantine-bucket';
    const projectId = process.env.GOOGLE_CLOUD_PROJECT;
    const keyFilename = process.env.GOOGLE_APPLICATION_CREDENTIALS;

    const config: any = {};
    if (projectId) config.projectId = projectId;
    if (keyFilename && fs.existsSync(keyFilename)) config.keyFilename = keyFilename;

    this.storage = new Storage(config);
  }

  async upload(localPath: string, cloudObjectName: string): Promise<boolean> {
    try {
      if (!fs.existsSync(localPath)) return false;
      const bucket = this.storage.bucket(this.bucketName);

      // Compute sha256 before uploading to store in custom metadata
      const crypto = await import('node:crypto');
      const buffer = fs.readFileSync(localPath);
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

      await bucket.upload(localPath, {
        destination: cloudObjectName,
        metadata: {
          metadata: { sha256 }
        }
      });
      return true;
    } catch (e) {
      console.error('[Google Cloud Storage Upload Error]:', e);
      return false;
    }
  }

  async verify(cloudObjectName: string, expectedSHA256: string, expectedSize: number): Promise<boolean> {
    try {
      const meta = await this.getMetadata(cloudObjectName);
      if (!meta || !meta.exists) return false;
      if (!meta.sha256) return false; // Missing SHA-256 metadata MUST result in failure
      if (meta.sha256 !== expectedSHA256) return false;
      if (meta.size === undefined || meta.size <= 0 || meta.size !== expectedSize) return false;
      return true;
    } catch {
      return false;
    }
  }

  async deleteRemote(cloudObjectName: string): Promise<boolean> {
    try {
      const file = this.storage.bucket(this.bucketName).file(cloudObjectName);
      await file.delete();
      return true;
    } catch {
      return false;
    }
  }

  async getMetadata(cloudObjectName: string): Promise<{ exists: boolean; sha256?: string; size?: number } | null> {
    try {
      const file = this.storage.bucket(this.bucketName).file(cloudObjectName);
      const [exists] = await file.exists();
      if (!exists) return { exists: false };

      const [metadata] = await file.getMetadata();
      const customSha256 = metadata.metadata?.sha256 ? String(metadata.metadata.sha256) : undefined;
      const size = Number(metadata.size) || 0;

      return {
        exists: true,
        sha256: customSha256,
        size
      };
    } catch {
      return { exists: false };
    }
  }
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
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.copyFileSync(localPath, targetPath);
      return fs.existsSync(targetPath);
    } catch (e) {
      console.error('[Cloud Storage Upload Error]:', e);
      return false;
    }
  }

  async verify(cloudObjectName: string, expectedSHA256: string, expectedSize: number): Promise<boolean> {
    try {
      const meta = await this.getMetadata(cloudObjectName);
      if (!meta || !meta.exists) return false;
      if (!meta.sha256) return false;
      if (meta.sha256 !== expectedSHA256) return false;
      if (meta.size === undefined || meta.size <= 0 || meta.size !== expectedSize) return false;
      return true;
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

/**
 * Returns the configured CloudStorageProvider: Real GCS if bucket env var is set, otherwise Local Mock Provider.
 */
export function getCloudStorageProvider(): CloudStorageProvider {
  if (process.env.GOOGLE_CLOUD_BUCKET) {
    return new GoogleCloudStorageProvider();
  }
  return new LocalCloudStorageProvider();
}
