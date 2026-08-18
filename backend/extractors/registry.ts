import path from 'node:path';
import fs from 'node:fs';
import { BaseExtractor, ExtractionResult } from './base.js';
import { TXTExtractor } from './txtExtractor.js';
import { CSVExtractor } from './csvExtractor.js';
import { XLSXExtractor } from './xlsxExtractor.js';
import { DOCXExtractor } from './docxExtractor.js';
import { PPTXExtractor } from './pptxExtractor.js';
import { PDFExtractor } from './pdfExtractor.js';
import { ImageOcrExtractor } from './imageOcrExtractor.js';

export class ExtractorRegistry {
  private extractors: BaseExtractor[] = [];

  constructor() {
    this.extractors = [
      new TXTExtractor(),
      new CSVExtractor(),
      new XLSXExtractor(),
      new DOCXExtractor(),
      new PPTXExtractor(),
      new PDFExtractor(),
      new ImageOcrExtractor()
    ];
  }

  public getExtractor(filePath: string): BaseExtractor | null {
    for (const extractor of this.extractors) {
      if (extractor.canHandle(filePath)) {
        return extractor;
      }
    }
    return null;
  }

  public async extract(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
    const extractor = this.getExtractor(filePath);
    const ext = path.extname(filePath).toLowerCase();

    if (!extractor) {
      const stats = fs.existsSync(filePath) ? fs.statSync(filePath) : null;
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats ? stats.size : 0,
          unsupported: true
        },
        links: [],
        embeddedObjects: [],
        structure: {},
        warnings: [`Unsupported file extension '${ext}'`]
      };
    }

    try {
      return await extractor.extract(filePath, maxFileSizeMB);
    } catch (err: any) {
      const stats = fs.existsSync(filePath) ? fs.statSync(filePath) : null;
      return {
        text: '',
        metadata: {
          extension: ext,
          size: stats ? stats.size : 0,
          error: true
        },
        links: [],
        embeddedObjects: [],
        structure: {},
        warnings: [`Extraction error: ${err.message || 'Fatal parser error'}`]
      };
    }
  }
}

export const defaultRegistry = new ExtractorRegistry();

export async function extractFile(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
  return defaultRegistry.extract(filePath, maxFileSizeMB);
}
