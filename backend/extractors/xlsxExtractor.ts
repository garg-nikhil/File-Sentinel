import fs from 'node:fs';
import path from 'node:path';
import * as XLSX from 'xlsx';
import JSZip from 'jszip';
import { XMLParser } from 'fast-xml-parser';
import { BaseExtractor, ExtractionResult, TableData } from './base.js';

export class XLSXExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.xlsx' || ext === '.xlsm';
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
          extension: '.xlsx',
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          skipped: true,
          error: true
        },
        links,
        embeddedObjects,
        structure,
        warnings
      };
    }

    const fileBuffer = fs.readFileSync(filePath);

    // --- ARCHIVE BOMB & ZIP INSPECTION ---
    const { inspectZipArchive, RESOURCE_LIMITS } = await import('../resourceLimits.js');
    const zipCheck = await inspectZipArchive(fileBuffer);
    if (!zipCheck.valid) {
      warnings.push(zipCheck.reason || 'RESOURCE_LIMIT_EXCEEDED: Archive inspection failed.');
      return {
        text: '',
        metadata: {
          extension: '.xlsx',
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          error: true,
          resourceLimitExceeded: true
        },
        links,
        embeddedObjects,
        structure,
        warnings
      };
    }

    let wb: XLSX.WorkBook;

    try {
      wb = XLSX.read(fileBuffer, {
        type: 'buffer',
        cellFormula: true,
        cellDates: true
      });
    } catch (err: any) {
      warnings.push(`XLSX read error: ${err.message || 'Corrupt or locked workbook'}`);
      return {
        text: '',
        metadata: { extension: '.xlsx', size: stats.size, error: true },
        links,
        embeddedObjects,
        structure,
        warnings
      };
    }

    // --- STEP 1: OOXML Package Inspection via JSZip ---
    let zip: JSZip | null = null;
    try {
      zip = await JSZip.loadAsync(fileBuffer);
    } catch (zipErr) {
      warnings.push('File is not a valid ZIP/OOXML package or is encrypted.');
    }

    const xmlParser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

    if (zip) {
      // Check for VBA / Macros
      if (zip.file('xl/vbaProject.bin')) {
        structure.hasVBA = true;
        warnings.push('VBA Macro project binary (vbaProject.bin) detected.');
      }

      // Check for embedded objects
      const embeddings = Object.keys(zip.files).filter(f => f.startsWith('xl/embeddings/') || f.includes('oleObject'));
      if (embeddings.length > 0) {
        structure.embeddings = embeddings;
        embeddings.forEach(emb => embeddedObjects.push(emb));
        warnings.push(`Embedded object reference identified: ${embeddings.join(', ')}`);
      }

      // Check for external relationships in xl/_rels/
      const relFiles = Object.keys(zip.files).filter(f => f.startsWith('xl/_rels/') || f.includes('.rels'));
      for (const relFile of relFiles) {
        try {
          const relXml = await zip.file(relFile)?.async('text');
          if (relXml) {
            const relObj = xmlParser.parse(relXml);
            const relationships = relObj?.Relationships?.Relationship;
            const relArray = Array.isArray(relationships) ? relationships : (relationships ? [relationships] : []);

            for (const rel of relArray) {
              const target = rel['@_Target'];
              const mode = rel['@_TargetMode'];
              if (mode === 'External' || (target && (target.startsWith('http://') || target.startsWith('https://')))) {
                if (target && !links.includes(target)) links.push(target);
                warnings.push(`External link relationship detected: ${target}`);
              }
            }
          }
        } catch {
          // ignore rel parse error
        }
      }

      // Check sheet visibility directly from xl/workbook.xml
      try {
        const wbXml = await zip.file('xl/workbook.xml')?.async('text');
        if (wbXml) {
          const wbObj = xmlParser.parse(wbXml);
          const sheets = wbObj?.workbook?.sheets?.sheet;
          const sheetArray = Array.isArray(sheets) ? sheets : (sheets ? [sheets] : []);

          structure.sheetMetadata = sheetArray.map((s: any) => ({
            name: s['@_name'],
            sheetId: s['@_sheetId'],
            state: s['@_state'] || 'visible'
          }));

          for (const s of sheetArray) {
            const state = s['@_state'];
            const name = s['@_name'];
            if (state === 'hidden') {
              warnings.push(`Hidden Excel worksheet detected: ${name} (hidden)`);
            } else if (state === 'veryHidden') {
              warnings.push(`Very hidden Excel worksheet detected: ${name} (veryHidden)`);
            }
          }
        }
      } catch {
        // ignore wbXml parse error
      }
    }

    // --- STEP 2: SheetJS Cell & Content Extraction ---
    const sheetNames = wb.SheetNames;
    structure.sheetNames = sheetNames;
    structure.sheetCount = sheetNames.length;

    // Defined Names
    if (wb.Workbook && wb.Workbook.Names) {
      structure.definedNames = wb.Workbook.Names.map(n => ({ name: n.Name, ref: n.Ref }));
    }

    const textParts: string[] = [];
    textParts.push(`Workbook: ${path.basename(filePath)}`);
    textParts.push(`Sheets (${sheetNames.length}): ${sheetNames.join(', ')}`);

    for (const sheetName of sheetNames) {
      const sheet = wb.Sheets[sheetName];
      if (!sheet) continue;

      const range = XLSX.utils.decode_range(sheet['!ref'] || 'A1:A1');
      const hiddenRows: number[] = [];
      const hiddenCols: number[] = [];

      // Check hidden rows/cols metadata in SheetJS
      if (sheet['!rows']) {
        sheet['!rows'].forEach((r, idx) => {
          if (r && r.hidden) hiddenRows.push(idx + 1);
        });
      }
      if (sheet['!cols']) {
        sheet['!cols'].forEach((c, idx) => {
          if (c && c.hidden) hiddenCols.push(idx + 1);
        });
      }

      if (hiddenRows.length > 0) warnings.push(`Sheet '${sheetName}' contains hidden rows: ${hiddenRows.join(', ')}`);
      if (hiddenCols.length > 0) warnings.push(`Sheet '${sheetName}' contains hidden columns: ${hiddenCols.join(', ')}`);

      textParts.push(`\n--- Sheet: ${sheetName} ---`);

      // Convert sheet to JSON rows for tabular representation
      const sheetJson: unknown[][] = XLSX.utils.sheet_to_json(sheet, { header: 1, raw: false, defval: '' });
      if (sheetJson.length > 0) {
        tables.push({
          name: sheetName,
          headers: (sheetJson[0] as string[]).map(h => String(h || '')),
          rows: sheetJson.slice(1)
        });
      }

      // Iterate through cells to extract value, formula, comments, hyperlinks
      for (let R = range.s.r; R <= range.e.r; ++R) {
        const rowCells: string[] = [];
        for (let C = range.s.c; C <= range.e.c; ++C) {
          const cellAddress = XLSX.utils.encode_cell({ r: R, c: C });
          const cell = sheet[cellAddress];
          if (!cell) continue;

          let cellStr = '';
          if (cell.v !== undefined && cell.v !== null) {
            cellStr = String(cell.v);
          }

          // Formulas as string data (DO NOT EXECUTE)
          if (cell.f) {
            cellStr += ` [Formula: =${cell.f}]`;
          }

          // Cell comment
          if (cell.c) {
            const commentTxt = Array.isArray(cell.c) ? cell.c.map(c => c.t).join(' ') : (cell.c.t || '');
            cellStr += ` [Comment: ${commentTxt}]`;
          }

          // Cell Hyperlink
          if (cell.l && cell.l.Target) {
            cellStr += ` [Link: ${cell.l.Target}]`;
            if (!links.includes(cell.l.Target)) links.push(cell.l.Target);
          }

          if (cellStr.trim().length > 0) {
            rowCells.push(`${cellAddress}=(${cellStr})`);
          }
        }

        if (rowCells.length > 0) {
          textParts.push(`Row ${R + 1}: ${rowCells.join(' | ')}`);
        }
      }
    }

    let fullText = textParts.join('\n');
    if (fullText.length > RESOURCE_LIMITS.maxExtractedTextBytes) {
      fullText = fullText.substring(0, RESOURCE_LIMITS.maxExtractedTextBytes);
      warnings.push('RESOURCE_LIMIT_EXCEEDED: Extracted text exceeded maximum allowed limit. Truncated; evidence incomplete.');
      structure.truncated = true;
    }

    return {
      text: fullText,
      tables,
      metadata: {
        extension: '.xlsx',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        sheetCount: sheetNames.length,
        sheetNames,
        author: wb.Props?.Author || undefined,
        title: wb.Props?.Title || undefined
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
