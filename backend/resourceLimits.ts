import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';

export interface ResourceLimits {
  maxFileSizeBytes: number;
  maxPdfSizeBytes: number;
  maxDocxSizeBytes: number;
  maxXlsxSizeBytes: number;
  maxPptxSizeBytes: number;
  maxCsvSizeBytes: number;
  maxTxtSizeBytes: number;
  maxExtractedTextBytes: number;
  maxCsvRows: number;
  maxWorksheetCells: number;
  maxArchiveEntries: number;
  maxArchiveExpandedBytes: number;
  maxArchiveDepth: number;
  maxBatchFiles: number;
  maxConcurrentParsers: number;
  processingTimeoutMs: number;
}

export const RESOURCE_LIMITS: ResourceLimits = {
  maxFileSizeBytes: 50 * 1024 * 1024, // 50 MB
  maxPdfSizeBytes: 50 * 1024 * 1024,
  maxDocxSizeBytes: 50 * 1024 * 1024,
  maxXlsxSizeBytes: 50 * 1024 * 1024,
  maxPptxSizeBytes: 50 * 1024 * 1024,
  maxCsvSizeBytes: 20 * 1024 * 1024,
  maxTxtSizeBytes: 20 * 1024 * 1024,
  maxExtractedTextBytes: 5 * 1024 * 1024, // 5 MB extracted text
  maxCsvRows: 50000,
  maxWorksheetCells: 100000,
  maxArchiveEntries: 1000,
  maxArchiveExpandedBytes: 150 * 1024 * 1024, // 150 MB uncompressed
  maxArchiveDepth: 2,
  maxBatchFiles: 5000,
  maxConcurrentParsers: 4,
  processingTimeoutMs: 30000 // 30 seconds
};

export function getFileLimitForExt(ext: string): number {
  const normalized = ext.toLowerCase();
  switch (normalized) {
    case '.pdf': return RESOURCE_LIMITS.maxPdfSizeBytes;
    case '.docx':
    case '.docm': return RESOURCE_LIMITS.maxDocxSizeBytes;
    case '.xlsx':
    case '.xlsm': return RESOURCE_LIMITS.maxXlsxSizeBytes;
    case '.pptx':
    case '.pptm': return RESOURCE_LIMITS.maxPptxSizeBytes;
    case '.csv': return RESOURCE_LIMITS.maxCsvSizeBytes;
    case '.txt': return RESOURCE_LIMITS.maxTxtSizeBytes;
    default: return RESOURCE_LIMITS.maxFileSizeBytes;
  }
}

export async function inspectZipArchive(fileBuffer: Buffer, currentDepth: number = 0): Promise<{ valid: boolean; reason?: string }> {
  if (currentDepth > RESOURCE_LIMITS.maxArchiveDepth) {
    return { valid: false, reason: 'RESOURCE_LIMIT_EXCEEDED: Nested archive depth exceeded maximum allowed limit.' };
  }

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(fileBuffer);
  } catch (err: any) {
    return { valid: false, reason: `RESOURCE_LIMIT_EXCEEDED: Invalid or corrupted archive: ${err.message}` };
  }

  const entries = Object.keys(zip.files);
  if (entries.length > RESOURCE_LIMITS.maxArchiveEntries) {
    return { valid: false, reason: `RESOURCE_LIMIT_EXCEEDED: Archive entry count (${entries.length}) exceeds maximum allowed limit (${RESOURCE_LIMITS.maxArchiveEntries}).` };
  }

  let totalUncompressedBytes = 0;
  for (const filename of entries) {
    const entry = zip.files[filename];
    if (!entry) continue;

    // Check for nested zip archives inside the package
    if (filename.toLowerCase().endsWith('.zip') || filename.toLowerCase().endsWith('.docx') || filename.toLowerCase().endsWith('.xlsx')) {
      try {
        const nestedBuffer = await entry.async('nodebuffer');
        const nestedCheck = await inspectZipArchive(nestedBuffer, currentDepth + 1);
        if (!nestedCheck.valid) {
          return nestedCheck;
        }
      } catch {
        // ignore nested check error if unreadable
      }
    }

    // Estimate uncompressed size if available
    // @ts-ignore
    const uncompressedSize = entry._data ? entry._data.uncompressedSize : 0;
    if (uncompressedSize) {
      totalUncompressedBytes += uncompressedSize;
    }
  }

  if (totalUncompressedBytes > RESOURCE_LIMITS.maxArchiveExpandedBytes) {
    return { valid: false, reason: `RESOURCE_LIMIT_EXCEEDED: Uncompressed archive expansion size (${totalUncompressedBytes} bytes) exceeds limit (${RESOURCE_LIMITS.maxArchiveExpandedBytes} bytes).` };
  }

  return { valid: true };
}

export function withTimeout<T>(promise: Promise<T>, timeoutMs: number = RESOURCE_LIMITS.processingTimeoutMs): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const err: any = new Error('PROCESSING_TIMEOUT: Document extraction exceeded maximum allowed processing time.');
      err.code = 'PROCESSING_TIMEOUT';
      reject(err);
    }, timeoutMs);

    promise.then(
      (res) => {
        clearTimeout(timer);
        resolve(res);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
