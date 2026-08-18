import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../db.js';
import { AuditParameter } from '../audit/models.js';

export interface ChecklistManifest {
  id: string;
  version: string;
  name: string;
  description: string;
  publisher: string;
  minimumEngineVersion: string;
  controlCount: number;
  categoryWeights?: Record<string, number>;
  createdAt?: string;
  updatedAt?: string;
}

export interface ChecklistControl {
  id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  domain: string;
  evidence_requirements: string[];
  supported_formats: string[];
  required_fields: string[];
  evaluation_type: string;
  logic: 'SINGLE' | 'OR' | 'AND' | 'GROUP';
  fatal?: boolean;
  keywords: string[];
  requires_validity_check?: boolean;
  expiry_required?: boolean;
  requires_human_review?: boolean;
  distinguish_policy?: boolean;
  evaluation_rules?: string[];
  enabled?: boolean;
}

export interface ChecklistPackage {
  manifest: ChecklistManifest;
  controls: ChecklistControl[];
  enabled: boolean;
  installedAt: string;
  updatedAt: string;
}

export class ChecklistManager {
  private db: DatabaseSync;
  public static CURRENT_ENGINE_VERSION = '8.2.0';

  constructor(db?: DatabaseSync) {
    this.db = db || getDatabase();
    this.ensureTables();
  }

  private ensureTables(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS checklist_packages (
          id TEXT PRIMARY KEY,
          version TEXT NOT NULL,
          name TEXT NOT NULL,
          description TEXT NOT NULL,
          publisher TEXT NOT NULL,
          minimum_engine_version TEXT NOT NULL,
          control_count INTEGER NOT NULL,
          enabled INTEGER DEFAULT 1,
          manifest_json TEXT NOT NULL,
          controls_json TEXT NOT NULL,
          installed_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);
    } catch {}
  }

  private validatePropertiesAllowlist(manifest: any, controls: any[]): string[] {
    const errors: string[] = [];
    const allowedManifestKeys = new Set([
      'id', 'version', 'name', 'description', 'publisher', 'minimumEngineVersion', 'controlCount', 'categoryWeights', 'createdAt', 'updatedAt'
    ]);
    const allowedControlKeys = new Set([
      'id', 'name', 'category', 'severity', 'description', 'domain', 'evidence_requirements', 'supported_formats', 'required_fields', 'evaluation_type', 'logic', 'fatal', 'keywords', 'requires_validity_check', 'expiry_required', 'requires_human_review', 'distinguish_policy', 'evaluation_rules', 'enabled'
    ]);

    // Check manifest keys & types
    for (const key of Object.keys(manifest)) {
      if (!allowedManifestKeys.has(key)) {
        errors.push(`Checklist manifest contains disallowed property: '${key}'`);
      }
      const val = manifest[key];
      if (key === 'categoryWeights' && val !== undefined) {
        if (typeof val !== 'object' || Array.isArray(val) || val === null) {
          errors.push('manifest.categoryWeights must be a simple key-value object.');
        } else {
          for (const k of Object.keys(val)) {
            if (typeof val[k] !== 'number') {
              errors.push(`manifest.categoryWeights['${k}'] must be a number.`);
            }
          }
        }
      } else if (key === 'controlCount') {
        if (typeof val !== 'number') errors.push('manifest.controlCount must be a number.');
      } else if (val !== undefined && typeof val !== 'string') {
        errors.push(`manifest.${key} must be a string.`);
      }
    }

    // Check each control keys & types
    for (let idx = 0; idx < (controls || []).length; idx++) {
      const c = controls[idx];
      if (!c || typeof c !== 'object' || Array.isArray(c)) {
        errors.push(`Control at index ${idx} must be a valid object.`);
        continue;
      }
      for (const key of Object.keys(c)) {
        if (!allowedControlKeys.has(key)) {
          errors.push(`Control '${c.id || idx}' contains disallowed property: '${key}'`);
        }
        const val = c[key];
        if (val === undefined) continue;

        if (['fatal', 'requires_validity_check', 'expiry_required', 'requires_human_review', 'distinguish_policy', 'enabled'].includes(key)) {
          if (typeof val !== 'boolean') {
            errors.push(`Control '${c.id || idx}' property '${key}' must be a boolean.`);
          }
        } else if (['evidence_requirements', 'supported_formats', 'required_fields', 'keywords', 'evaluation_rules'].includes(key)) {
          if (!Array.isArray(val)) {
            errors.push(`Control '${c.id || idx}' property '${key}' must be an array.`);
          } else {
            for (let j = 0; j < val.length; j++) {
              if (typeof val[j] !== 'string') {
                errors.push(`Control '${c.id || idx}' property '${key}' element at index ${j} must be a string.`);
              }
            }
          }
        } else {
          if (typeof val !== 'string') {
            errors.push(`Control '${c.id || idx}' property '${key}' must be a string.`);
          }
        }
      }
    }

    return errors;
  }

  public validatePackage(manifest: ChecklistManifest, controls: ChecklistControl[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const CURRENT_ENGINE_VERSION = '8.2.0';

    const validateInputSafetyRecursive = (val: any, depth: number = 0): void => {
      if (depth > 3) {
        throw new Error('Checklist contains deeply nested objects exceeding safety limit of 3 levels.');
      }
      if (val === null || val === undefined) {
        return;
      }
      if (typeof val === 'object') {
        const keys = Object.keys(val);
        if (keys.length > 30) {
          throw new Error('Checklist object contains an excessive number of properties.');
        }
        for (const key of keys) {
          if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            throw new Error(`SECURITY VIOLATION: Forbidden prototype key '${key}' detected.`);
          }
          const propertyDescriptor = Object.getOwnPropertyDescriptor(val, key);
          if (propertyDescriptor && (propertyDescriptor.get || propertyDescriptor.set)) {
            throw new Error('SECURITY VIOLATION: Forbidden getter/setter property descriptor detected.');
          }
          validateInputSafetyRecursive(val[key], depth + 1);
        }
      }
    };

    try {
      validateInputSafetyRecursive(manifest);
      validateInputSafetyRecursive(controls);
    } catch (err: any) {
      errors.push(`SECURITY VIOLATION: ${err.message}`);
      return { valid: false, errors };
    }

    if (!manifest || typeof manifest !== 'object') {
      return { valid: false, errors: ['Manifest object missing or invalid.'] };
    }

    // Properties allowlist & type validation
    const allowlistErrors = this.validatePropertiesAllowlist(manifest, controls);
    errors.push(...allowlistErrors);

    if (!manifest.id || typeof manifest.id !== 'string' || !/^[A-Z0-9_-]+$/i.test(manifest.id)) {
      errors.push(`Invalid checklist ID: '${manifest.id}'. Must be alphanumeric with hyphens/underscores.`);
    }

    if (!manifest.version || !/^\d+\.\d+\.\d+/.test(manifest.version)) {
      errors.push(`Invalid semantic version: '${manifest.version}'. Format must be X.Y.Z.`);
    }

    if (!manifest.name || manifest.name.trim().length < 3) {
      errors.push('Checklist name must be at least 3 characters.');
    }

    // Engine compatibility check
    if (manifest.minimumEngineVersion) {
      const minVer = manifest.minimumEngineVersion;
      const [minMajor, minMinor] = minVer.split('.').map(Number);
      const [curMajor, curMinor] = CURRENT_ENGINE_VERSION.split('.').map(Number);
      if (minMajor > curMajor || (minMajor === curMajor && minMinor > curMinor)) {
        errors.push(`Incompatible engine version: Checklist requires v${minVer}, but current engine is v${CURRENT_ENGINE_VERSION}.`);
      }
    }

    if (!Array.isArray(controls) || controls.length === 0) {
      errors.push('Checklist must contain at least one control.');
    }

    if (controls && controls.length !== manifest.controlCount) {
      errors.push(`Control count mismatch: Manifest specifies ${manifest.controlCount}, but ${controls.length} controls provided.`);
    }

    // Executable payload security check (reject code injection attempts)
    const jsonStr = JSON.stringify({ manifest, controls }).toLowerCase();
    const forbiddenPatterns = ['eval(', 'function(', 'process.', 'child_process', 'exec(', '<script>', 'require(', 'import(', '__proto__'];
    for (const pat of forbiddenPatterns) {
      if (jsonStr.includes(pat)) {
        errors.push(`SECURITY VIOLATION: Executable payload pattern '${pat}' detected in checklist package. Packages must be purely declarative JSON.`);
      }
    }

    const controlIds = new Set<string>();
    for (let i = 0; i < (controls || []).length; i++) {
      const c = controls[i];
      if (!c.id) {
        errors.push(`Control at index ${i} is missing an ID.`);
      } else if (controlIds.has(c.id)) {
        errors.push(`Duplicate control ID '${c.id}' found in package.`);
      } else {
        controlIds.add(c.id);
      }

      if (!c.domain || c.domain.trim().length === 0) {
        errors.push(`Control '${c.id || i}' must specify a non-empty evidence domain.`);
      }

      if (!['SINGLE', 'OR', 'AND', 'GROUP'].includes(c.logic)) {
        errors.push(`Control '${c.id || i}' has invalid evaluation logic '${c.logic}'.`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  public installPackage(manifest: ChecklistManifest, controls: ChecklistControl[]): ChecklistPackage {
    const validation = this.validatePackage(manifest, controls);
    if (!validation.valid) {
      throw new Error(`Checklist validation failed: ${validation.errors.join('; ')}`);
    }

    const now = new Date().toISOString();
    const existing = this.getPackage(manifest.id);

    if (existing) {
      return this.updatePackage(manifest.id, manifest, controls);
    }

    this.db.prepare(`
      INSERT INTO checklist_packages (
        id, version, name, description, publisher, minimum_engine_version,
        control_count, enabled, manifest_json, controls_json, installed_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    `).run(
      manifest.id,
      manifest.version,
      manifest.name,
      manifest.description || '',
      manifest.publisher || 'Unknown Publisher',
      manifest.minimumEngineVersion || '1.0.0',
      controls.length,
      JSON.stringify(manifest),
      JSON.stringify(controls),
      now,
      now
    );

    return {
      manifest,
      controls,
      enabled: true,
      installedAt: now,
      updatedAt: now
    };
  }

  public updatePackage(id: string, manifest: ChecklistManifest, controls: ChecklistControl[]): ChecklistPackage {
    const validation = this.validatePackage(manifest, controls);
    if (!validation.valid) {
      throw new Error(`Checklist update validation failed: ${validation.errors.join('; ')}`);
    }

    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE checklist_packages SET
        version = ?,
        name = ?,
        description = ?,
        publisher = ?,
        minimum_engine_version = ?,
        control_count = ?,
        manifest_json = ?,
        controls_json = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      manifest.version,
      manifest.name,
      manifest.description || '',
      manifest.publisher || '',
      manifest.minimumEngineVersion || '1.0.0',
      controls.length,
      JSON.stringify(manifest),
      JSON.stringify(controls),
      now,
      id
    );

    return {
      manifest,
      controls,
      enabled: true,
      installedAt: now,
      updatedAt: now
    };
  }

  public setEnabled(id: string, enabled: boolean): boolean {
    const res = this.db.prepare('UPDATE checklist_packages SET enabled = ?, updated_at = ? WHERE id = ?')
      .run(enabled ? 1 : 0, new Date().toISOString(), id);
    return res.changes > 0;
  }

  public removePackage(id: string): boolean {
    const res = this.db.prepare('DELETE FROM checklist_packages WHERE id = ?').run(id);
    return res.changes > 0;
  }

  public getPackage(id: string): ChecklistPackage | null {
    const row = this.db.prepare('SELECT * FROM checklist_packages WHERE id = ?').get(id) as any;
    if (!row) return null;

    try {
      return {
        manifest: JSON.parse(row.manifest_json),
        controls: JSON.parse(row.controls_json),
        enabled: row.enabled === 1,
        installedAt: row.installed_at,
        updatedAt: row.updated_at
      };
    } catch {
      return null;
    }
  }

  public listPackages(filterEnabledOnly: boolean = false): ChecklistPackage[] {
    const query = filterEnabledOnly
      ? 'SELECT * FROM checklist_packages WHERE enabled = 1 ORDER BY id ASC'
      : 'SELECT * FROM checklist_packages ORDER BY id ASC';

    const rows = this.db.prepare(query).all() as any[];
    const result: ChecklistPackage[] = [];

    for (const row of rows) {
      try {
        result.push({
          manifest: JSON.parse(row.manifest_json),
          controls: JSON.parse(row.controls_json),
          enabled: row.enabled === 1,
          installedAt: row.installed_at,
          updatedAt: row.updated_at
        });
      } catch {}
    }

    return result;
  }

  /**
   * Convert package controls to standard AuditParameter[] format for engine
   */
  public toAuditParameters(packageId: string): AuditParameter[] {
    const pkg = this.getPackage(packageId);
    if (!pkg) return [];

    return pkg.controls.map(c => ({
      id: c.id,
      category: c.category as any,
      category_name: c.category.replace(/_/g, ' '),
      category_weight: pkg.manifest.categoryWeights?.[c.category] || (c.category === 'ZERO_TOLERANCE' ? 100 : 50),
      parameter: c.name,
      domain: c.domain as any,
      fatal: c.fatal ?? (c.category === 'ZERO_TOLERANCE'),
      severity: c.severity,
      required_evidence: c.evidence_requirements || [],
      keywords: c.keywords || [],
      logic: c.logic,
      requires_validity_check: c.requires_validity_check,
      expiry_required: c.expiry_required,
      requires_human_review: c.requires_human_review,
      distinguish_policy: c.distinguish_policy,
      evaluation_rules: c.evaluation_rules || [c.description],
      enabled: c.enabled ?? true
    }));
  }

  /**
   * Load and sync checklist packages from root checklists directory
   */
  public syncFromDisk(checklistsDir: string = './checklists'): number {
    if (!fs.existsSync(checklistsDir)) return 0;

    let synced = 0;
    const entries = fs.readdirSync(checklistsDir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const pkgDir = path.join(checklistsDir, entry.name);
        const manifestPath = path.join(pkgDir, 'manifest.json');
        const controlsPath = path.join(pkgDir, 'controls.json');

        if (fs.existsSync(manifestPath) && fs.existsSync(controlsPath)) {
          try {
            const manifest: ChecklistManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            const controls: ChecklistControl[] = JSON.parse(fs.readFileSync(controlsPath, 'utf8'));
            this.installPackage(manifest, controls);
            synced++;
          } catch (e) {
            console.error(`Failed to load checklist package from ${pkgDir}:`, e);
          }
        }
      }
    }

    return synced;
  }
}
