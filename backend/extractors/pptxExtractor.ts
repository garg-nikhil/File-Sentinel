import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';
import { XMLParser } from 'fast-xml-parser';
import { BaseExtractor, ExtractionResult, TableData } from './base.js';

export class PPTXExtractor extends BaseExtractor {
  public canHandle(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.pptx' || ext === '.pptm';
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
          extension: '.pptx',
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
          extension: '.pptx',
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

    let zip: JSZip | null = null;

    try {
      zip = await JSZip.loadAsync(fileBuffer);
    } catch {
      warnings.push('File is not a valid ZIP/OOXML PPTX package.');
      return {
        text: '',
        metadata: { extension: '.pptx', size: stats.size, error: true },
        links,
        embeddedObjects,
        structure,
        warnings
      };
    }

    const xmlParser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

    let author: string | undefined;
    let title: string | undefined;

    // --- STEP 1: Core Metadata ---
    try {
      const coreXml = await zip.file('docProps/core.xml')?.async('text');
      if (coreXml) {
        const coreObj = xmlParser.parse(coreXml);
        const coreProps = coreObj?.['cp:coreProperties'] || coreObj?.coreProperties;
        if (coreProps) {
          author = coreProps['dc:creator'] || coreProps['cp:lastModifiedBy'];
          title = coreProps['dc:title'];
        }
      }
    } catch {
      // ignore
    }

    // --- STEP 2: Check Presentation Structure & Hidden Slides ---
    const hiddenSlides: string[] = [];
    try {
      const presXml = await zip.file('ppt/presentation.xml')?.async('text');
      if (presXml) {
        const presObj = xmlParser.parse(presXml);
        const sldIdList = presObj?.['p:presentation']?.['p:sldIdLst']?.['p:sldId'];
        const slideArray = Array.isArray(sldIdList) ? sldIdList : (sldIdList ? [sldIdList] : []);

        slideArray.forEach((s: any, idx: number) => {
          if (s['@_show'] === '0' || s['@_show'] === 'false') {
            hiddenSlides.push(`Slide ${idx + 1}`);
          }
        });

        if (hiddenSlides.length > 0) {
          structure.hiddenSlides = hiddenSlides;
          warnings.push(`Presentation contains hidden slides: ${hiddenSlides.join(', ')}`);
        }
      }
    } catch {
      // ignore
    }

    // Check for Embedded Objects
    const embeddings = Object.keys(zip.files).filter(f => f.startsWith('ppt/embeddings/') || f.includes('oleObject'));
    if (embeddings.length > 0) {
      structure.embeddings = embeddings;
      embeddings.forEach(e => embeddedObjects.push(e));
      warnings.push(`Embedded objects identified in presentation: ${embeddings.join(', ')}`);
    }

    // --- STEP 3: Slides & Speaker Notes Text Extraction ---
    const slideFiles = Object.keys(zip.files)
      .filter(f => /^ppt\/slides\/slide\d+\.xml$/.test(f))
      .sort((a, b) => {
        const numA = parseInt(a.match(/\d+/)?.[0] || '0', 10);
        const numB = parseInt(b.match(/\d+/)?.[0] || '0', 10);
        return numA - numB;
      });

    structure.slideCount = slideFiles.length;

    const textParts: string[] = [
      `Presentation: ${path.basename(filePath)}`,
      title ? `Title: ${title}` : '',
      author ? `Author: ${author}` : ''
    ].filter(Boolean);

    for (let i = 0; i < slideFiles.length; i++) {
      const slidePath = slideFiles[i];
      const slideNum = i + 1;
      const isHidden = hiddenSlides.includes(`Slide ${slideNum}`);

      try {
        const slideXml = await zip.file(slidePath)?.async('text');
        if (slideXml) {
          // Extract text from text run tags <a:t>
          const textMatches = slideXml.match(/<a:t[^>]*>(.*?)<\/a:t>/gi);
          let slideText = '';
          if (textMatches) {
            slideText = textMatches
              .map(t => t.replace(/<[^>]+>/g, '').trim())
              .filter(Boolean)
              .join(' ');
          }

          textParts.push(`\n--- Slide ${slideNum}${isHidden ? ' (Hidden)' : ''} ---`);
          if (slideText) {
            textParts.push(slideText);
          }

          // Check slide relationships for links
          const relPath = `ppt/slides/_rels/${path.basename(slidePath)}.rels`;
          const relXml = await zip.file(relPath)?.async('text');
          if (relXml) {
            const relObj = xmlParser.parse(relXml);
            const relationships = relObj?.Relationships?.Relationship;
            const relArray = Array.isArray(relationships) ? relationships : (relationships ? [relationships] : []);

            for (const rel of relArray) {
              const target = rel['@_Target'];
              const mode = rel['@_TargetMode'];
              if (mode === 'External' || (target && (target.startsWith('http://') || target.startsWith('https://')))) {
                if (target && !links.includes(target)) links.push(target);
                warnings.push(`Slide ${slideNum} external relationship: ${target}`);
              }
            }
          }
        }
      } catch {
        // ignore
      }

      // Check corresponding Speaker Notes
      const notesPath = `ppt/notesSlides/notesSlide${slideNum}.xml`;
      if (zip.file(notesPath)) {
        try {
          const notesXml = await zip.file(notesPath)?.async('text');
          if (notesXml) {
            const notesMatches = notesXml.match(/<a:t[^>]*>(.*?)<\/a:t>/gi);
            if (notesMatches) {
              const notesText = notesMatches
                .map(t => t.replace(/<[^>]+>/g, '').trim())
                .filter(Boolean)
                .join(' ');
              if (notesText.length > 0) {
                textParts.push(`[Speaker Notes - Slide ${slideNum}]: ${notesText}`);
              }
            }
          }
        } catch {
          // ignore
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
        extension: '.pptx',
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        author,
        title,
        slideCount: slideFiles.length
      },
      links,
      embeddedObjects,
      structure,
      warnings
    };
  }
}
