import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { BUILTIN_RULES } from '../src/rules/builtinRules.js';

let dbInstance: DatabaseSync | null = null;

export function getDatabase(dbPath: string = './filesentinel.db'): DatabaseSync {
  if (dbInstance) return dbInstance;

  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  const initDb = (filePath: string): DatabaseSync => {
    const db = new DatabaseSync(filePath);

    // Initialize Tables
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        root_path TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        status TEXT NOT NULL,
        total_files INTEGER DEFAULT 0,
        supported_files INTEGER DEFAULT 0,
        processed_files INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        safe_count INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        path TEXT NOT NULL,
        filename TEXT NOT NULL,
        extension TEXT NOT NULL,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        risk_score INTEGER DEFAULT 0,
        classification TEXT DEFAULT 'INTERNAL',
        scan_status TEXT DEFAULT 'SUCCESS',
        created_at TEXT,
        modified_at TEXT,
        extracted_text_preview TEXT,
        metadata_json TEXT,
        warnings_json TEXT,
        ai_summary_json TEXT
      );

      CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        file_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence_json TEXT,
        confidence REAL DEFAULT 1.0,
        source TEXT DEFAULT 'RULE',
        recommendation TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        pattern TEXT NOT NULL,
        description TEXT,
        recommendation TEXT,
        is_builtin INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS quarantine_items (
        id TEXT PRIMARY KEY,
        file_id TEXT NOT NULL,
        original_path TEXT NOT NULL,
        filename TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        cloud_object TEXT,
        upload_status TEXT DEFAULT 'NONE',
        verification_status TEXT DEFAULT 'NONE',
        deletion_status TEXT DEFAULT 'NOT_DELETED',
        quarantined_at TEXT NOT NULL,
        verified_at TEXT,
        deleted_at TEXT,
        logs_json TEXT
      );

      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        file_path TEXT,
        sha256 TEXT,
        user_identity TEXT,
        status TEXT NOT NULL,
        details TEXT
      );
    `);

    // Seed default built-in rules if table is empty
    const countRow = db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number };
    if (countRow.count === 0) {
      const insertRule = db.prepare(`
        INSERT INTO rules (id, name, category, severity, enabled, pattern, description, recommendation, is_builtin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
      `);
      for (const r of BUILTIN_RULES) {
        insertRule.run(
          r.id,
          r.name,
          r.category,
          r.severity,
          r.enabled ? 1 : 0,
          r.pattern,
          r.description,
          r.recommendation
        );
      }
    }

    return db;
  };

  try {
    dbInstance = initDb(dbPath);
  } catch (err: any) {
    if (err?.code === 'ERR_SQLITE_ERROR' || err?.message?.includes('malformed')) {
      console.warn(`[SQLite] Database corrupt (${err.message}). Removing and recreating fresh database.`);
      try {
        if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
        if (fs.existsSync(`${dbPath}-journal`)) fs.unlinkSync(`${dbPath}-journal`);
        if (fs.existsSync(`${dbPath}-wal`)) fs.unlinkSync(`${dbPath}-wal`);
      } catch (unlinkErr) {
        console.error('[SQLite] Unlink error:', unlinkErr);
      }
      dbInstance = initDb(dbPath);
    } else {
      throw err;
    }
  }

  return dbInstance;
}
