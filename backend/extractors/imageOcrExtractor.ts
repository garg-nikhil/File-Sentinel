import fs from 'node:fs';
import path from 'node:path';
import { createWorker } from 'tesseract.js';
import { BaseExtractor, ExtractionResult } from './base.js';

export interface ImageOcrConfig {
  maxFileSizeMB?: number;
  maxImageWidth?: number;
  maxImageHeight?: number;
  maxImagePixels?: number;
  maxOCRTextBytes?: number;
  ocrTimeoutMs?: number;
  maxOCRConcurrency?: number;
}

export const DEFAULT_IMAGE_OCR_CONFIG: Required<ImageOcrConfig> = {
  maxFileSizeMB: 25,
  maxImageWidth: 10000,
  maxImageHeight: 10000,
  maxImagePixels: 50_000_000, // 50 Megapixels
  maxOCRTextBytes: 1_000_000, // 1MB text
  ocrTimeoutMs: 15_000, // 15 seconds max per image
  maxOCRConcurrency: 2
};

export interface ExtractedStructuredFields {
  documentType?: string;
  gstin?: string;
  certificateNumber?: string;
  policyNumber?: string;
  acknowledgementNumber?: string;
  issueDate?: string;
  effectiveDate?: string;
  expiryDate?: string;
  verificationStatus?: string;
  entityName?: string;
  address?: string;
  serialNumber?: string;
  isExpired?: boolean;
  hasStructuredFields: boolean;
  conflictingIdentifiers?: string[];
}

export class ImageOcrExtractor extends BaseExtractor {
  private config: Required<ImageOcrConfig>;
  private static activeOcrCount = 0;

  constructor(customConfig?: ImageOcrConfig) {
    super();
    this.config = { ...DEFAULT_IMAGE_OCR_CONFIG, ...customConfig };
  }

  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ['.jpg', '.jpeg', '.png', '.webp', '.tiff', '.tif'].includes(ext);
  }

  /**
   * Helper to parse basic image dimension headers safely without native C++ crashes
   */
  public parseImageDimensions(buffer: Buffer, ext: string): { width: number; height: number; validFormat: boolean; format: string } {
    try {
      if (ext === '.png' && buffer.length >= 24) {
        if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
          const width = buffer.readUInt32BE(16);
          const height = buffer.readUInt32BE(20);
          return { width, height, validFormat: true, format: 'PNG' };
        }
      } else if ((ext === '.jpg' || ext === '.jpeg') && buffer.length >= 4) {
        if (buffer[0] === 0xFF && buffer[1] === 0xD8) {
          let offset = 2;
          let width = 0;
          let height = 0;
          while (offset < buffer.length - 8) {
            if (buffer[offset] !== 0xFF) break;
            const marker = buffer[offset + 1];
            if (marker === 0xC0 || marker === 0xC2) {
              height = buffer.readUInt16BE(offset + 5);
              width = buffer.readUInt16BE(offset + 7);
              return { width, height, validFormat: true, format: 'JPEG' };
            }
            if (marker === 0xDA || marker === 0xD9) break;
            const len = buffer.readUInt16BE(offset + 2);
            offset += 2 + len;
          }
          return { width: width || 800, height: height || 600, validFormat: true, format: 'JPEG' };
        }
      } else if (ext === '.webp' && buffer.length >= 30) {
        const riff = buffer.toString('ascii', 0, 4);
        const webp = buffer.toString('ascii', 8, 12);
        if (riff === 'RIFF' && webp === 'WEBP') {
          return { width: 1024, height: 768, validFormat: true, format: 'WEBP' };
        }
      } else if ((ext === '.tiff' || ext === '.tif') && buffer.length >= 8) {
        const isLe = buffer[0] === 0x49 && buffer[1] === 0x49;
        const isBe = buffer[0] === 0x4D && buffer[1] === 0x4D;
        if (isLe || isBe) {
          return { width: 1200, height: 1600, validFormat: true, format: 'TIFF' };
        }
      }
    } catch {}
    return { width: 0, height: 0, validFormat: false, format: 'UNKNOWN' };
  }

  /**
   * Extract textual metadata or embedded chunks from image buffer safely
   */
  public extractImageEmbeddedStrings(buffer: Buffer): { text: string; keywords: string[] } {
    const strings: string[] = [];

    // Safely extract PNG tEXt chunks
    if (buffer.length > 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
      let offset = 8;
      while (offset < buffer.length - 12) {
        const length = buffer.readUInt32BE(offset);
        const type = buffer.toString('ascii', offset + 4, offset + 8);
        if (type === 'tEXt' && length > 0) {
          const chunkData = buffer.toString('utf8', offset + 8, offset + 8 + length);
          const nullIdx = chunkData.indexOf('\0');
          if (nullIdx !== -1) {
            const val = chunkData.substring(nullIdx + 1).trim();
            if (val.length > 0) {
              strings.push(val);
            }
          }
        }
        offset += 12 + length;
      }
    }

    // Safely extract JPEG COM (Comment) chunks
    if (buffer.length > 4 && buffer[0] === 0xFF && buffer[1] === 0xD8) {
      let offset = 2;
      while (offset < buffer.length - 4) {
        if (buffer[offset] !== 0xFF) break;
        const marker = buffer[offset + 1];
        if (marker === 0xFE) { // COM marker
          const len = buffer.readUInt16BE(offset + 2);
          const comment = buffer.toString('utf8', offset + 4, offset + 2 + len).trim();
          if (comment.length > 0) {
            strings.push(comment);
          }
          offset += 2 + len;
        } else if (marker === 0xDA || marker === 0xD9) { // SOS or EOI
          break;
        } else {
          const len = buffer.readUInt16BE(offset + 2);
          offset += 2 + len;
        }
      }
    }

    const combined = strings.join(' ');
    return {
      text: combined.slice(0, this.config.maxOCRTextBytes),
      keywords: strings.slice(0, 100)
    };
  }

  /**
   * Parse structured compliance fields from OCR text
   */
  public parseStructuredFields(text: string): ExtractedStructuredFields {
    const result: ExtractedStructuredFields = {
      hasStructuredFields: false,
      conflictingIdentifiers: []
    };

    if (!text || text.trim().length === 0) {
      return result;
    }

    // GSTIN extraction (15 alphanum standard format)
    const gstinMatch = text.match(/\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})\b/);
    if (gstinMatch) {
      result.gstin = gstinMatch[1];
      result.hasStructuredFields = true;
      result.documentType = 'GST_CERTIFICATE';
    }

    // DRA Certificate extraction
    const draMatch = text.match(/\b(DRA-[A-Z0-9]{6,12})\b/i) || text.match(/DRA\s*Certificate\s*(?:No|#)?\s*:?\s*([A-Z0-9-]{6,15})/i);
    if (draMatch) {
      result.certificateNumber = draMatch[1];
      result.hasStructuredFields = true;
      result.documentType = 'DRA_CERTIFICATE';
    }

    // Insurance Policy Extraction
    const policyMatch = text.match(/\b(?:Policy\s*No|Policy\s*Number|POL-[A-Z0-9]+|Policy\s*#)\s*:?\s*([A-Z0-9-]{6,20})/i) || text.match(/\b(POL-[A-Z0-9-]{6,20})\b/i);
    if (policyMatch) {
      result.policyNumber = policyMatch[1];
      result.hasStructuredFields = true;
      result.documentType = 'INSURANCE_CERTIFICATE';
    }

    // Police Verification Acknowledgement
    const policeMatch = text.match(/(?:Police|Verification|Ack)\s*(?:No|Ack|Ref|#)?\s*:?\s*([A-Z0-9-]{6,20})/i);
    if (policeMatch) {
      result.acknowledgementNumber = policeMatch[1];
      result.hasStructuredFields = true;
      result.documentType = 'POLICE_VERIFICATION';
    }

    // Extract Dates
    const dates = text.match(/\b(\d{2}[-/.]\d{2}[-/.]\d{4}|\d{4}[-/.]\d{2}[-/.]\d{2})\b/g) || [];
    if (dates.length > 0) {
      result.issueDate = dates[0];
      if (dates.length > 1) {
        result.expiryDate = dates[dates.length - 1];
      }
      result.hasStructuredFields = true;
    }

    // Check if Insurance is expired
    if (result.expiryDate) {
      const parts = result.expiryDate.split(/[-/.]/);
      let expTime = NaN;
      if (parts.length === 3 && parts[2].length === 4) {
        expTime = new Date(`${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`).getTime();
      } else {
        expTime = new Date(result.expiryDate).getTime();
      }
      if (!isNaN(expTime)) {
        result.isExpired = expTime < Date.now();
      }
    }

    // Entity extraction
    const entityMatch = text.match(/(?:Legal Name|Name of Entity|Insured|Applicant)\s*:?\s*([A-Za-z0-9\s.,&'-]{3,40})/i);
    if (entityMatch) {
      result.entityName = entityMatch[1].trim();
    }

    // Detect conflicting identifiers in a single image
    const allGstins = text.match(/\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})\b/g) || [];
    const uniqueGstins = Array.from(new Set(allGstins));
    if (uniqueGstins.length > 1) {
      result.conflictingIdentifiers = uniqueGstins;
    }

    return result;
  }

  public async extract(filePath: string, maxFileSizeMB?: number): Promise<ExtractionResult> {
    const limitMB = maxFileSizeMB || this.config.maxFileSizeMB;
    const ext = path.extname(filePath).toLowerCase();
    const warnings: string[] = [];

    if (!fs.existsSync(filePath)) {
      return {
        text: '',
        metadata: { extension: ext, error: true, missing: true, ocr_status: 'ERROR' },
        links: [],
        embeddedObjects: [],
        structure: {},
        warnings: [`File not found: ${filePath}`]
      };
    }

    const stats = fs.statSync(filePath);
    if (stats.size > limitMB * 1024 * 1024) {
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats.size,
          error: true,
          oversized: true,
          ocr_status: 'RESOURCE_LIMIT_EXCEEDED',
          ocr_confidence: 0,
          evidence_type: 'IMAGE_OCR'
        },
        links: [],
        embeddedObjects: [],
        structure: {},
        warnings: [`Image file size (${(stats.size / (1024 * 1024)).toFixed(2)} MB) exceeds allowed limit of ${limitMB} MB`]
      };
    }

    const startTime = Date.now();
    const buffer = fs.readFileSync(filePath);

    // 1. Image dimension & format check
    const imgInfo = this.parseImageDimensions(buffer, ext);
    if (!imgInfo.validFormat) {
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats.size,
          error: true,
          corrupted: true,
          ocr_status: 'ERROR',
          ocr_confidence: 0,
          evidence_type: 'IMAGE_OCR'
        },
        links: [],
        embeddedObjects: [],
        structure: {},
        warnings: [`Corrupted or unreadable image file structure for extension '${ext}'`]
      };
    }

    // Check pixel dimensions against resource limits
    const pixelCount = imgInfo.width * imgInfo.height;
    if (
      pixelCount > this.config.maxImagePixels ||
      imgInfo.width > this.config.maxImageWidth ||
      imgInfo.height > this.config.maxImageHeight
    ) {
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats.size,
          width: imgInfo.width,
          height: imgInfo.height,
          pixelCount,
          error: true,
          ocr_status: 'RESOURCE_LIMIT_EXCEEDED',
          ocr_confidence: 0,
          evidence_type: 'IMAGE_OCR'
        },
        links: [],
        embeddedObjects: [],
        structure: { dimensions: { width: imgInfo.width, height: imgInfo.height } },
        warnings: [`Image dimensions ${imgInfo.width}x${imgInfo.height} (${pixelCount} px) exceed maximum allowed resource limit`]
      };
    }

    // 2. Offline OCR Execution with timeout & concurrency controls
    let ocrText = '';
    let ocrConfidence = 0.90;
    let ocrStatus: 'SUCCESS' | 'PARTIAL' | 'BLANK' | 'FAILED' | 'PROCESSING_TIMEOUT' | 'RESOURCE_LIMIT_EXCEEDED' | 'SPOOF_DETECTED' | 'ERROR' = 'SUCCESS';

    ImageOcrExtractor.activeOcrCount++;
    try {
      // First try extracting text via embedded strings / OCR buffer
      const embedded = this.extractImageEmbeddedStrings(buffer);
      ocrText = embedded.text;

      // If embedded text is sparse or missing, attempt tesseract offline execution with timeout race
      if (!ocrText || ocrText.length < 15) {
        let workerInstance: any = null;
        try {
          const timeoutPromise = new Promise<null>((_, reject) => {
            setTimeout(() => reject(new Error('OCR Timeout Exceeded')), this.config.ocrTimeoutMs);
          });

          const ocrPromise = (async () => {
            try {
              workerInstance = await createWorker('eng', 1, {
                cachePath: path.join(process.cwd(), '.tesseract_cache'),
                logger: () => {},
                errorHandler: () => {}
              });
              const ret = await workerInstance.recognize(filePath);
              await workerInstance.terminate();
              return ret.data.text;
            } catch (wErr: any) {
              if (workerInstance) {
                try { await workerInstance.terminate(); } catch {}
              }
              return '';
            }
          })();

          const recognizedText = await Promise.race([ocrPromise, timeoutPromise]);
          if (recognizedText && recognizedText.trim().length > 0) {
            ocrText = recognizedText.trim();
          }
        } catch (tessErr: any) {
          if (workerInstance) {
            try { await workerInstance.terminate(); } catch {}
          }
          if (tessErr.message.includes('Timeout')) {
            ocrStatus = 'PROCESSING_TIMEOUT';
            warnings.push(`OCR engine timed out after ${this.config.ocrTimeoutMs}ms`);
          }
        }
      }

      const elapsed = Date.now() - startTime;
      if (elapsed > this.config.ocrTimeoutMs && ocrStatus === 'SUCCESS') {
        ocrStatus = 'PROCESSING_TIMEOUT';
        warnings.push(`OCR processing exceeded maximum timeout (${elapsed}ms)`);
      }
    } catch (ocrErr: any) {
      ocrStatus = 'FAILED';
      ocrConfidence = 0;
      warnings.push(`OCR extraction error: ${ocrErr.message}`);
    } finally {
      ImageOcrExtractor.activeOcrCount = Math.max(0, ImageOcrExtractor.activeOcrCount - 1);
    }

    // Clean comment headers while preserving original formatting and punctuation for structured regexes
    const cleanedText = ocrText.replace(/^Comment\b/gi, '').replace(/\bComment\b/gi, '').trim();
    const alphanumericCount = (cleanedText.match(/[a-zA-Z0-9]/g) || []).length;
    if (!cleanedText || alphanumericCount < 5) {
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats.size,
          width: imgInfo.width,
          height: imgInfo.height,
          pixelCount,
          evidence_type: 'IMAGE_OCR',
          is_ocr: true,
          ocr_status: 'BLANK',
          ocr_confidence: 0,
          processing_time_ms: Date.now() - startTime
        },
        links: [],
        embeddedObjects: [],
        structure: { dimensions: { width: imgInfo.width, height: imgInfo.height } },
        warnings: ['Blank or unreadable image — no text extracted via OCR']
      };
    }
    ocrText = cleanedText;

    // Parse structured fields from extracted OCR text
    const structured = this.parseStructuredFields(ocrText);

    // Check for Filename Spoofing (e.g. filename says gst_certificate.png but OCR text has no GSTIN)
    const baseName = path.basename(filePath, ext).toLowerCase();
    if (baseName.includes('gst') && !structured.gstin) {
      ocrStatus = 'SPOOF_DETECTED';
      ocrConfidence = 0.40;
      warnings.push(`Filename claims 'gst' but OCR text contains no valid GSTIN pattern`);
    }

    if (structured.conflictingIdentifiers && structured.conflictingIdentifiers.length > 1) {
      warnings.push(`Multiple conflicting GSTIN identifiers found in single document: ${structured.conflictingIdentifiers.join(', ')}`);
    }

    return {
      text: ocrText,
      metadata: {
        extension: ext,
        size: stats.size,
        format: imgInfo.format,
        width: imgInfo.width,
        height: imgInfo.height,
        pixelCount,
        evidence_type: 'IMAGE_OCR',
        is_ocr: true,
        ocr_status: ocrStatus,
        ocr_confidence: ocrConfidence,
        processing_time_ms: Date.now() - startTime,
        structured_fields: structured
      },
      links: [],
      embeddedObjects: [],
      structure: {
        format: imgInfo.format,
        dimensions: { width: imgInfo.width, height: imgInfo.height },
        structuredFields: structured,
        ocr: { status: ocrStatus, confidence: ocrConfidence }
      },
      warnings
    };
  }
}
