import fs from 'node:fs';
import path from 'node:path';
import { BaseExtractor, ExtractionResult, TableData } from './base.js';
import { PDFParse } from 'pdf-parse';

export class PDFExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.pdf';
  }

  public async extract(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
    const warnings: string[] = [];
    const links: string[] = [];
    const embeddedObjects: string[] = [];
    const structure: Record<string, unknown> = {};
    const tables: TableData[] = [];

    const stats = fs.statSync(filePath);
    const maxBytes = maxFileSizeMB * 1024 * 1024;
    
    if (stats.size > maxBytes) {
      warnings.push(`File size (${stats.size} bytes) exceeds configured limit (${maxFileSizeMB} MB)`);
      return {
        text: '',
        metadata: {
          extension: '.pdf',
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          skipped: true
        },
        links,
        embeddedObjects,
        structure,
        warnings
      };
    }

    const fileBuffer = fs.readFileSync(filePath);
    let pdfText = '';
    let pageCount = 0;
    let pdfInfo: any = {};

    try {
      const parser = new PDFParse({ data: fileBuffer });
      const textResult = await parser.getText();
      const infoResult = await parser.getInfo();
      pdfText = textResult.text || '';
      pageCount = textResult.total || 0;
      pdfInfo = infoResult.info || {};
    } catch (err: any) {
      warnings.push(`PDF parse error: ${err.message || 'Corrupt or encrypted PDF file'}`);
    }

    const rawPdfStr = fileBuffer.toString('latin1');
    
    // Fallback: If pdf-parse returned empty text, extract text streams (Tj operators)
    if (!pdfText.trim()) {
      const streamMatches = rawPdfStr.match(/\(([^()]+)\)\s*Tj/g);
      if (streamMatches) {
        pdfText = streamMatches.map(m => m.replace(/\(([^()]+)\)\s*Tj/, '$1')).join('\n');
      }
    }

    if (/\/JS\b|\/JavaScript\b|\/S\s*\/JavaScript/.test(rawPdfStr)) {
      structure.hasJavaScript = true;
      warnings.push('PDF contains interactive JavaScript actions.');
    }
    
    if (/\/Launch\b|\/Action\s*\/Launch/.test(rawPdfStr)) {
      structure.hasLaunchActions = true;
      warnings.push('PDF contains external application Launch actions.');
    }
    
    if (/\/EmbeddedFiles\b|\/EF\b/.test(rawPdfStr)) {
      structure.hasEmbeddedFiles = true;
      embeddedObjects.push('Embedded PDF Attachments');
      warnings.push('PDF contains embedded file attachments.');
    }

    if (/\/Encrypt\b/.test(rawPdfStr)) {
      structure.isEncrypted = true;
      warnings.push('PDF object encryption stream detected.');
    }
    
    if (/\/Annots\b/.test(rawPdfStr)) {
      structure.hasAnnotations = true;
    }

    // Extract links found in PDF raw text or URI dictionaries
    const urlRegex = /https?:\/\/[^\s"'<>\(\)]+/gi;
    let match;
    while ((match = urlRegex.exec(pdfText + rawPdfStr)) !== null) {
      if (!links.includes(match[0])) links.push(match[0]);
      if (links.length >= 50) break;
    }

    structure.pageCount = pageCount;
    
    const textHeader = [
      `PDF Document: ${path.basename(filePath)}`,
      pdfInfo.Title ? `Title: ${pdfInfo.Title}` : '',
      pdfInfo.Author ? `Author: ${pdfInfo.Author}` : '',
      `Page Count: ${pageCount}`,
      ''
    ].filter(Boolean).join('\n');

    let fullText = `${textHeader}\n${pdfText}`;
    
    const { RESOURCE_LIMITS } = await import('../resourceLimits.js');
    if (fullText.length > RESOURCE_LIMITS.maxExtractedTextBytes) {
      fullText = fullText.substring(0, RESOURCE_LIMITS.maxExtractedTextBytes);
      warnings.push('RESOURCE_LIMIT_EXCEEDED: Extracted text exceeded maximum allowed limit. Truncated; evidence incomplete.');
      structure.truncated = true;
    }

    return {
      text: fullText,
      tables,
      metadata: {
        extension: '.pdf',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        pageCount,
        title: pdfInfo.Title || undefined,
        author: pdfInfo.Author || undefined,
        creator: pdfInfo.Creator || undefined,
        producer: pdfInfo.Producer || undefined
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
