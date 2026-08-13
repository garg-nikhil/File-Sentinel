export interface TableData {
  name?: string;
  headers?: string[];
  rows?: unknown[][];
}

export interface ExtractionResult {
  text: string;
  tables?: TableData[];
  metadata: Record<string, unknown>;
  links: string[];
  embeddedObjects: string[];
  structure: Record<string, unknown>;
  warnings: string[];
}

export abstract class BaseExtractor {
  abstract canHandle(filePath: string): boolean;
  abstract extract(filePath: string, maxFileSizeMB?: number): Promise<ExtractionResult>;
}
