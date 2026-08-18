import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

export interface ImageFixtureOptions {
  filename: string;
  width?: number;
  height?: number;
  textPayload?: string;
  corruptHeader?: boolean;
}

/**
 * Creates genuine PNG binary image files for adversarial testing
 */
export function createSyntheticPngImage(dir: string, options: ImageFixtureOptions): string {
  const filePath = path.join(dir, options.filename);
  const width = options.width || 800;
  const height = options.height || 600;

  if (options.corruptHeader) {
    fs.writeFileSync(filePath, Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
    return filePath;
  }

  // PNG Magic Header: 89 50 4E 47 0D 0A 1A 0A
  const header = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

  // IHDR chunk data (13 bytes)
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 6; // color type (RGBA)
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace

  const ihdrTypeAndData = Buffer.concat([Buffer.from('IHDR', 'ascii'), ihdrData]);
  const ihdrCrc = zlib.crc32(ihdrTypeAndData);

  const ihdrChunk = Buffer.alloc(8 + 13 + 4);
  ihdrChunk.writeUInt32BE(13, 0);
  ihdrTypeAndData.copy(ihdrChunk, 4);
  ihdrChunk.writeUInt32BE(ihdrCrc, 4 + 17);

  // tEXt Chunk with raw text payload
  const textContent = options.textPayload || '';
  const key = 'Comment\0';
  const textChunkLen = Buffer.byteLength(key) + Buffer.byteLength(textContent, 'utf8');
  const textChunkData = Buffer.alloc(textChunkLen);
  textChunkData.write(key, 0, 'ascii');
  textChunkData.write(textContent, key.length, 'utf8');

  const textTypeAndData = Buffer.concat([Buffer.from('tEXt', 'ascii'), textChunkData]);
  const textCrc = zlib.crc32(textTypeAndData);

  const textChunk = Buffer.alloc(8 + textChunkLen + 4);
  textChunk.writeUInt32BE(textChunkLen, 0);
  textTypeAndData.copy(textChunk, 4);
  textChunk.writeUInt32BE(textCrc, 4 + 4 + textChunkLen);

  // IDAT chunk (compressed pixel data: 1 byte filter per line + RGBA pixels)
  const rawPixelLines = Buffer.alloc(height * (1 + width * 4));
  const compressedPixels = zlib.deflateSync(rawPixelLines);
  const idatTypeAndData = Buffer.concat([Buffer.from('IDAT', 'ascii'), compressedPixels]);
  const idatCrc = zlib.crc32(idatTypeAndData);

  const idatChunk = Buffer.alloc(8 + compressedPixels.length + 4);
  idatChunk.writeUInt32BE(compressedPixels.length, 0);
  idatTypeAndData.copy(idatChunk, 4);
  idatChunk.writeUInt32BE(idatCrc, 4 + 4 + compressedPixels.length);

  // IEND chunk
  const iendTypeAndData = Buffer.from('IEND', 'ascii');
  const iendCrc = zlib.crc32(iendTypeAndData);
  const iendChunk = Buffer.alloc(12);
  iendChunk.writeUInt32BE(0, 0);
  iendTypeAndData.copy(iendChunk, 4);
  iendChunk.writeUInt32BE(iendCrc, 8);

  const fullPng = Buffer.concat([header, ihdrChunk, textChunk, idatChunk, iendChunk]);
  fs.writeFileSync(filePath, fullPng);
  return filePath;
}
