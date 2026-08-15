import fs from 'node:fs';
import path from 'node:path';
import { BaseExtractor, ExtractionResult } from './base.js';

export class TXTExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.txt';
  }

  public async extract(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
    const warnings: string[] = [];
    const links: string[] = [];
    const embeddedObjects: string[] = [];
    const structure: Record<string, unknown> = {};

    const stats = fs.statSync(filePath);
    const { RESOURCE_LIMITS } = await import('../resourceLimits.js');
    const maxBytes = Math.min(maxFileSizeMB * 1024 * 1024, RESOURCE_LIMITS.maxTxtSizeBytes);

    if (stats.size > maxBytes) {
      warnings.push(`File size (${stats.size} bytes) exceeds configured limit (${maxFileSizeMB} MB)`);
      return {
        text: '',
        metadata: {
          extension: '.txt',
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

    const buffer = fs.readFileSync(filePath);
    let text = '';
    let encoding = 'utf-8';

    // UTF-16 LE BOM (0xFF 0xFE) or UTF-16 BE BOM (0xFE 0xFF)
    if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
      encoding = 'utf16le';
      text = buffer.toString('utf16le');
    } else if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
      encoding = 'utf16be';
      // Node.js doesn't natively support utf16be in toString, swap bytes
      const swapped = Buffer.alloc(buffer.length);
      for (let i = 0; i < buffer.length - 1; i += 2) {
        swapped[i] = buffer[i + 1];
        swapped[i + 1] = buffer[i];
      }
      text = swapped.toString('utf16le');
    } else {
      try {
        text = buffer.toString('utf-8');
      } catch {
        encoding = 'latin1';
        text = buffer.toString('latin1');
      }
    }

    if (text.length > RESOURCE_LIMITS.maxExtractedTextBytes) {
      text = text.substring(0, RESOURCE_LIMITS.maxExtractedTextBytes);
      warnings.push('RESOURCE_LIMIT_EXCEEDED: Extracted text exceeded maximum allowed limit. Truncated; evidence incomplete.');
      structure.truncated = true;
    }

    const lines = text.split(/\r\n|\r|\n/);
    structure.lineCount = lines.length;

    // Extract URLs/links statically
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    let match;
    while ((match = urlRegex.exec(text)) !== null) {
      if (!links.includes(match[0])) {
        links.push(match[0]);
      }
      if (links.length >= 50) break;
    }

    return {
      text,
      metadata: {
        extension: '.txt',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        encoding,
        lineCount: lines.length
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
