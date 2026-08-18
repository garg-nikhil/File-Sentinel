import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { createCanvas } from '@napi-rs/canvas';

export interface ImageFixtureOptions {
  filename: string;
  width?: number;
  height?: number;
  textPayload?: string;
  corruptHeader?: boolean;
}

/**
 * Creates genuine PNG binary image files with visual rendered text for OCR testing
 */
export function createSyntheticPngImage(dir: string, options: ImageFixtureOptions): string {
  const filePath = path.join(dir, options.filename);
  const width = options.width || 800;
  const height = options.height || 600;

  if (options.corruptHeader) {
    fs.writeFileSync(filePath, Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
    return filePath;
  }

  // Render text onto canvas if payload is provided
  const canvas = createCanvas(width, height);
  const ctx = canvas.getContext('2d');

  // Fill canvas background
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, width, height);

  if (options.textPayload && options.textPayload.trim().length > 0) {
    ctx.fillStyle = '#000000';
    ctx.font = 'bold 24px sans-serif';

    // Break text payload into multiple lines
    const text = options.textPayload;
    const words = text.split(' ');
    let line = '';
    let y = 60;
    const lineHeight = 36;
    const maxLineWidth = width - 80;

    for (let i = 0; i < words.length; i++) {
      const testLine = line + words[i] + ' ';
      const metrics = ctx.measureText(testLine);
      if (metrics.width > maxLineWidth && i > 0) {
        ctx.fillText(line.trim(), 40, y);
        line = words[i] + ' ';
        y += lineHeight;
        if (y > height - 40) break;
      } else {
        line = testLine;
      }
    }
    if (line && y <= height - 20) {
      ctx.fillText(line.trim(), 40, y);
    }
  }

  const pngBuffer = canvas.toBuffer('image/png');
  fs.writeFileSync(filePath, pngBuffer);
  return filePath;
}
