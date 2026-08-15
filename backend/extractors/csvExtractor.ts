import fs from 'node:fs';
import path from 'node:path';
import { parse as parseCsv } from 'csv-parse/sync';
import { BaseExtractor, ExtractionResult, TableData } from './base.js';

export class CSVExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.csv';
  }

  public async extract(filePath: string, maxFileSizeMB: number = 50): Promise<ExtractionResult> {
    const warnings: string[] = [];
    const links: string[] = [];
    const embeddedObjects: string[] = [];
    const structure: Record<string, unknown> = {};

    const stats = fs.statSync(filePath);
    const { RESOURCE_LIMITS } = await import('../resourceLimits.js');
    const maxBytes = Math.min(maxFileSizeMB * 1024 * 1024, RESOURCE_LIMITS.maxCsvSizeBytes);

    if (stats.size > maxBytes) {
      warnings.push(`File size (${stats.size} bytes) exceeds configured limit (${maxFileSizeMB} MB)`);
      return {
        text: '',
        metadata: {
          extension: '.csv',
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

    const fileContent = fs.readFileSync(filePath, 'utf-8');
    let records: string[][] = [];

    try {
      records = parseCsv(fileContent, {
        relax_column_count: true,
        skip_empty_lines: true,
        trim: true
      });
    } catch (err: any) {
      warnings.push(`CSV parse warning: ${err.message || 'Malformed CSV format'}. Falling back to basic line splitting.`);
      const rawLines = fileContent.split(/\r\n|\r|\n/).filter(l => l.trim().length > 0);
      records = rawLines.map(line => line.split(',').map(cell => cell.trim()));
    }

    if (records.length > RESOURCE_LIMITS.maxCsvRows) {
      warnings.push(`RESOURCE_LIMIT_EXCEEDED: CSV row count (${records.length}) exceeds maximum allowed limit (${RESOURCE_LIMITS.maxCsvRows}).`);
      records = records.slice(0, RESOURCE_LIMITS.maxCsvRows);
      structure.truncated = true;
    }

    const rowCount = records.length;
    const headers = rowCount > 0 ? records[0] : [];
    const dataRows = rowCount > 1 ? records.slice(1) : [];
    const columnCount = Math.max(...records.map(r => r.length), 0);

    structure.rowCount = rowCount;
    structure.columnCount = columnCount;
    structure.headers = headers;

    // Infer column data types from data rows
    const columnTypes: Record<string, string> = {};
    if (headers.length > 0 && dataRows.length > 0) {
      headers.forEach((h, colIndex) => {
        const sampleValues = dataRows.slice(0, 20).map(r => r[colIndex] || '');
        if (sampleValues.every(v => /^\d+$/.test(v))) {
          columnTypes[h] = 'INTEGER';
        } else if (sampleValues.every(v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))) {
          columnTypes[h] = 'EMAIL';
        } else if (sampleValues.every(v => /^[$€£]?[\d,]+(\.\d+)?$/.test(v))) {
          columnTypes[h] = 'CURRENCY';
        } else {
          columnTypes[h] = 'TEXT';
        }
      });
    }
    structure.inferredColumnTypes = columnTypes;

    // Format full CSV content into clean text so rule engine scans entire CSV
    const textLines: string[] = [];
    if (headers.length > 0) {
      textLines.push(`Headers: ${headers.join(' | ')}`);
    }

    records.forEach((row, idx) => {
      const lineStr = row.map((cell, cIdx) => {
        const colHeader = headers[cIdx] ? `${headers[cIdx]}: ` : '';
        return `${colHeader}${cell}`;
      }).join(' ; ');
      textLines.push(`Row ${idx + 1}: ${lineStr}`);

      // Extract URLs if present in cells
      row.forEach(cell => {
        if (cell.startsWith('http://') || cell.startsWith('https://')) {
          if (!links.includes(cell)) links.push(cell);
        }
      });
    });

    let fullText = textLines.join('\n');
    if (fullText.length > RESOURCE_LIMITS.maxExtractedTextBytes) {
      fullText = fullText.substring(0, RESOURCE_LIMITS.maxExtractedTextBytes);
      warnings.push('RESOURCE_LIMIT_EXCEEDED: Extracted text exceeded maximum allowed limit. Truncated; evidence incomplete.');
      structure.truncated = true;
    }

    const table: TableData = {
      name: path.basename(filePath),
      headers,
      rows: dataRows
    };

    return {
      text: fullText,
      tables: [table],
      metadata: {
        extension: '.csv',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        rowCount,
        columnCount
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
