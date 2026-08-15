import fs from 'node:fs';
import path from 'node:path';
import mammoth from 'mammoth';
import JSZip from 'jszip';
import { XMLParser } from 'fast-xml-parser';
import { BaseExtractor, ExtractionResult, TableData } from './base.js';

export class DOCXExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.docx' || ext === '.docm';
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
          extension: '.docx',
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
          extension: '.docx',
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

    // --- STEP 1: Main Text & Paragraphs Extraction via Mammoth ---
    let bodyText = '';
    try {
      const mammothResult = await mammoth.extractRawText({ buffer: fileBuffer });
      bodyText = mammothResult.value;
      if (mammothResult.messages && mammothResult.messages.length > 0) {
        mammothResult.messages.forEach(msg => {
          if (msg.type === 'warning') warnings.push(`Docx parser note: ${msg.message}`);
        });
      }
    } catch (mErr: any) {
      warnings.push(`DOCX text extraction error: ${mErr.message || 'Corrupt document body'}`);
    }

    // Enforce maxExtractedTextBytes
    if (bodyText.length > RESOURCE_LIMITS.maxExtractedTextBytes) {
      bodyText = bodyText.substring(0, RESOURCE_LIMITS.maxExtractedTextBytes);
      warnings.push('RESOURCE_LIMIT_EXCEEDED: Extracted text exceeded maximum allowed limit. Truncated; evidence incomplete.');
      structure.truncated = true;
    }

    // --- STEP 2: OOXML Zip Package Structure Inspection ---
    let author: string | undefined;
    let title: string | undefined;
    let revision: string | undefined;
    const extraTextParts: string[] = [];

    let zip: JSZip | null = null;
    try {
      zip = await JSZip.loadAsync(fileBuffer);
    } catch {
      warnings.push('File is not a valid ZIP/OOXML package.');
    }

    if (zip) {
      const xmlParser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

      // Core Properties (Author, Title, Revision)
      try {
        const coreXml = await zip.file('docProps/core.xml')?.async('text');
        if (coreXml) {
          const coreObj = xmlParser.parse(coreXml);
          const coreProps = coreObj?.['cp:coreProperties'] || coreObj?.coreProperties;
          if (coreProps) {
            author = coreProps['dc:creator'] || coreProps['cp:lastModifiedBy'];
            title = coreProps['dc:title'];
            revision = coreProps['cp:revision'];
            structure.author = author;
            structure.title = title;
            structure.revision = revision;
          }
        }
      } catch {
        // ignore coreXml parse error
      }

      // Check for Macros / VBA
      if (zip.file('word/vbaProject.bin')) {
        structure.hasVBA = true;
        warnings.push('VBA Macro project binary (vbaProject.bin) detected in document.');
      }

      // Check for Embedded Objects
      const embeddings = Object.keys(zip.files).filter(f => f.startsWith('word/embeddings/') || f.includes('oleObject'));
      if (embeddings.length > 0) {
        structure.embeddings = embeddings;
        embeddings.forEach(e => embeddedObjects.push(e));
        warnings.push(`Embedded OLE object or attachment identified: ${embeddings.join(', ')}`);
      }

      // Check Headers and Footers text
      const hfFiles = Object.keys(zip.files).filter(f => f.startsWith('word/header') || f.startsWith('word/footer'));
      for (const hfFile of hfFiles) {
        try {
          const hfXml = await zip.file(hfFile)?.async('text');
          if (hfXml) {
            const cleanText = hfXml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
            if (cleanText.length > 0) {
              extraTextParts.push(`Header/Footer [${path.basename(hfFile)}]: ${cleanText}`);
            }
          }
        } catch {
          // ignore
        }
      }

      // Check Comments
      try {
        const commentsXml = await zip.file('word/comments.xml')?.async('text');
        if (commentsXml) {
          const cleanComments = commentsXml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          if (cleanComments.length > 0) {
            extraTextParts.push(`Document Comments: ${cleanComments}`);
          }
        }
      } catch {
        // ignore
      }

      // Check External Relationships
      const relFiles = Object.keys(zip.files).filter(f => f.startsWith('word/_rels/'));
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
                warnings.push(`External relationship detected: ${target}`);
              }
            }
          }
        } catch {
          // ignore
        }
      }
    }

    // Extract links from body text as well
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    let match;
    while ((match = urlRegex.exec(bodyText)) !== null) {
      if (!links.includes(match[0])) links.push(match[0]);
    }

    const fullTextParts = [
      `Document: ${path.basename(filePath)}`,
      author ? `Author: ${author}` : '',
      title ? `Title: ${title}` : '',
      bodyText,
      ...extraTextParts
    ].filter(p => p.length > 0);

    const fullText = fullTextParts.join('\n\n');

    return {
      text: fullText,
      tables,
      metadata: {
        extension: '.docx',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        author,
        title,
        revision
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
