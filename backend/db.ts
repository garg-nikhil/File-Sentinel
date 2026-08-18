import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { BUILTIN_RULES } from '../src/rules/builtinRules.js';

let defaultDbInstance: DatabaseSync | null = null;

export function getOrGenerateOSProtectedKey(): string {
  if (process.env.FILE_SENTINEL_PROTECTED_KEY_OVERRIDE) {
    return process.env.FILE_SENTINEL_PROTECTED_KEY_OVERRIDE;
  }

  try {
    const baseDir = process.env.APPDATA || process.env.USERPROFILE || process.env.HOME || process.cwd();
    const keyDir = path.join(baseDir, '.filesentinel_protected');
    const keyPath = path.join(keyDir, 'protect.key');

    if (!fs.existsSync(keyDir)) {
      fs.mkdirSync(keyDir, { recursive: true });
    }

    if (fs.existsSync(keyPath)) {
      const existing = fs.readFileSync(keyPath, 'utf8').trim();
      if (existing.length >= 32) return existing;
    }

    const newKey = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(keyPath, newKey, { mode: 0o600, encoding: 'utf8' });
    return newKey;
  } catch {
    const fallbackSeed = process.env.USER || process.env.USERNAME || 'system-fallback';
    return crypto.createHash('sha256').update(fallbackSeed).digest('hex');
  }
}

export function getDatabase(dbPath: string = './filesentinel.db'): DatabaseSync {
  if (dbPath === './filesentinel.db' && defaultDbInstance) {
    return defaultDbInstance;
  }

  const dbDir = path.dirname(dbPath);
  if (dbPath !== ':memory:' && !fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  const initDb = (filePath: string): DatabaseSync => {
    const db = new DatabaseSync(filePath);

    // SQLCipher Encryption Setup (where compatible)
    const osKey = getOrGenerateOSProtectedKey();
    const keyHex = crypto.createHmac('sha256', osKey).update('filesentinel-salt-2026').digest('hex');
    db.exec(`PRAGMA key = '${keyHex}';`);

    // Verify DB integrity and fail closed on authentication/decryption failure
    try {
      if (process.env.FILE_SENTINEL_SIMULATE_TAMPERED_DB === 'true') {
        throw new Error('Simulated database tampering/corruption.');
      }
      const integrity = db.prepare('PRAGMA integrity_check').get() as { integrity_check: string } | undefined;
      if (!integrity || integrity.integrity_check !== 'ok') {
        throw new Error('SQLite integrity check failed or decryption key is incorrect.');
      }
    } catch (err: any) {
      console.error('[DATABASE SECURITY FATAL] Decryption/integrity check failed. FAILING CLOSED.', err.message);
      throw new Error(`SECURITY FATAL: Database decryption or integrity check failed. Fail-closed enforced. Reason: ${err.message}`);
    }

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
        extracted_text TEXT,
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

      CREATE TABLE IF NOT EXISTS file_cloud_uploads (
        file_id TEXT PRIMARY KEY,
        scan_id TEXT,
        audit_session_id TEXT,
        original_filename TEXT NOT NULL,
        local_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        cloud_bucket TEXT NOT NULL,
        cloud_object_name TEXT NOT NULL,
        upload_status TEXT NOT NULL,
        uploaded_at TEXT,
        verified_at TEXT,
        error_message TEXT
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

      CREATE TABLE IF NOT EXISTS audit_sessions (
        audit_id TEXT PRIMARY KEY,
        scan_id TEXT,
        org_id TEXT,
        audit_date TEXT NOT NULL,
        agency_name TEXT NOT NULL,
        auditor_name TEXT NOT NULL,
        status TEXT NOT NULL,
        total_parameters INTEGER DEFAULT 0,
        pass_count INTEGER DEFAULT 0,
        fail_count INTEGER DEFAULT 0,
        review_count INTEGER DEFAULT 0,
        not_found_count INTEGER DEFAULT 0,
        fatal_failures_count INTEGER DEFAULT 0,
        overall_score INTEGER DEFAULT 0,
        max_score INTEGER DEFAULT 200,
        overall_status TEXT NOT NULL,
        category_scores_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_parameter_results (
        audit_id TEXT NOT NULL,
        parameter_id TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence REAL DEFAULT 1.0,
        fatal INTEGER DEFAULT 0,
        score_earned REAL DEFAULT 0,
        max_score REAL DEFAULT 0,
        policy_status TEXT,
        pv_status TEXT,
        evidence_json TEXT,
        reason TEXT,
        missing_requirements_json TEXT,
        warnings_json TEXT,
        ai_recommendation_json TEXT,
        override_json TEXT,
        PRIMARY KEY (audit_id, parameter_id)
      );

      CREATE TABLE IF NOT EXISTS checklist_parameters (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        category_name TEXT NOT NULL,
        category_weight REAL DEFAULT 100,
        parameter TEXT NOT NULL,
        fatal INTEGER DEFAULT 0,
        severity TEXT DEFAULT 'HIGH',
        required_evidence_json TEXT,
        keywords_json TEXT,
        logic TEXT DEFAULT 'SINGLE',
        distinguish_policy INTEGER DEFAULT 0,
        requires_human_review INTEGER DEFAULT 0,
        evaluation_rules_json TEXT,
        enabled INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS audit_entities (
        entity_id TEXT NOT NULL,
        audit_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        display_name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        identifiers_json TEXT,
        evidence_references_json TEXT,
        matching_signals_json TEXT,
        confidence REAL DEFAULT 1.0,
        status TEXT NOT NULL,
        conflicts_json TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (audit_id, entity_id)
      );

      CREATE TABLE IF NOT EXISTS audit_entity_conflicts (
        id TEXT PRIMARY KEY,
        audit_id TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        conflict_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        reason TEXT NOT NULL,
        involved_evidence_json TEXT,
        conflicting_attributes_json TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS organizations (
        org_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        suspended INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scheduled_scan_logs (
        id TEXT PRIMARY KEY,
        scan_id TEXT,
        trigger_type TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        duration_ms INTEGER DEFAULT 0,
        target_paths_json TEXT,
        total_files INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        summary_message TEXT
      );

      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        disabled INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id)
      );

      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        revoked INTEGER DEFAULT 0,
        registered_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id)
      );

      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        device_id TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_audit_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        org_id TEXT,
        user_id TEXT,
        device_id TEXT,
        details TEXT,
        status TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS plans (
        plan_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        max_users INTEGER NOT NULL,
        max_devices INTEGER NOT NULL,
        scan_limit INTEGER NOT NULL,
        feature_flags TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS licenses (
        license_id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        status TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        grace_until TEXT,
        max_users INTEGER NOT NULL,
        max_devices INTEGER NOT NULL,
        scan_limit INTEGER NOT NULL,
        scans_used INTEGER DEFAULT 0,
        feature_flags TEXT NOT NULL,
        trial_start TEXT,
        trial_end TEXT,
        trial_status TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_validated_at TEXT,
        FOREIGN KEY (organization_id) REFERENCES organizations(org_id),
        FOREIGN KEY (plan_id) REFERENCES plans(plan_id)
      );

      CREATE TABLE IF NOT EXISTS license_devices (
        id TEXT PRIMARY KEY,
        license_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        last_seen_at TEXT NOT NULL,
        FOREIGN KEY (license_id) REFERENCES licenses(license_id),
        FOREIGN KEY (device_id) REFERENCES devices(device_id)
      );

      CREATE TABLE IF NOT EXISTS license_events (
        id TEXT PRIMARY KEY,
        license_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        details TEXT,
        actor_id TEXT
      );

      CREATE TABLE IF NOT EXISTS scan_telemetry (
        scan_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        duration_ms INTEGER NOT NULL,
        application_version TEXT NOT NULL,
        engine_version TEXT NOT NULL,
        checklist_version TEXT NOT NULL,
        files_discovered INTEGER NOT NULL,
        files_processed INTEGER NOT NULL,
        files_succeeded INTEGER NOT NULL,
        files_failed INTEGER NOT NULL,
        files_rejected_by_resource_limits INTEGER NOT NULL,
        pass_count INTEGER NOT NULL,
        review_count INTEGER NOT NULL,
        fail_count INTEGER NOT NULL,
        evidence_not_found_count INTEGER NOT NULL,
        critical_count INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        medium_count INTEGER NOT NULL,
        low_count INTEGER NOT NULL,
        overall_score REAL NOT NULL,
        parameters_evaluated INTEGER NOT NULL,
        scan_status TEXT NOT NULL,
        device_telemetry_json TEXT,
        debug_filenames_opt_in INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        ip_address TEXT,
        PRIMARY KEY (organization_id, scan_id)
      );

      CREATE TABLE IF NOT EXISTS telemetry_queue (
        queue_id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        attempts INTEGER DEFAULT 0,
        last_attempt_at TEXT,
        error_message TEXT,
        created_at TEXT NOT NULL,
        synced_at TEXT
      );

      CREATE TABLE IF NOT EXISTS billing_customers (
        customer_id TEXT PRIMARY KEY,
        org_id TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL DEFAULT 'RAZORPAY',
        provider_customer_id TEXT NOT NULL,
        email TEXT NOT NULL,
        name TEXT,
        billing_currency TEXT DEFAULT 'INR',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id)
      );

      CREATE TABLE IF NOT EXISTS subscriptions (
        subscription_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        customer_id TEXT NOT NULL,
        provider_subscription_id TEXT UNIQUE NOT NULL,
        plan_id TEXT NOT NULL,
        billing_interval TEXT NOT NULL, -- 'MONTHLY' | 'ANNUAL'
        status TEXT NOT NULL, -- 'TRIAL' | 'ACTIVE' | 'PAST_DUE' | 'GRACE_PERIOD' | 'EXPIRED' | 'CANCELLED'
        current_period_start TEXT NOT NULL,
        current_period_end TEXT NOT NULL,
        grace_until TEXT,
        trial_ends_at TEXT,
        cancel_at_period_end INTEGER DEFAULT 0,
        cancelled_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id),
        FOREIGN KEY (customer_id) REFERENCES billing_customers(customer_id),
        FOREIGN KEY (plan_id) REFERENCES plans(plan_id)
      );

      CREATE TABLE IF NOT EXISTS subscription_events (
        event_id TEXT PRIMARY KEY,
        subscription_id TEXT,
        org_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        previous_status TEXT,
        new_status TEXT,
        details_json TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS payment_events (
        payment_id TEXT PRIMARY KEY,
        subscription_id TEXT,
        org_id TEXT NOT NULL,
        provider_payment_id TEXT UNIQUE NOT NULL,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL DEFAULT 'INR',
        status TEXT NOT NULL, -- 'SUCCESS' | 'FAILURE' | 'PENDING'
        error_code TEXT,
        error_description TEXT,
        raw_payload_json TEXT,
        processed_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS processed_webhooks (
        event_id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        event_type TEXT NOT NULL,
        processed_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS privacy_retention_policies (
        org_id TEXT PRIMARY KEY,
        cloud_metadata_retention_days INTEGER DEFAULT 90,
        auto_purge_enabled INTEGER DEFAULT 1,
        last_purged_at TEXT,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id)
      );

      CREATE TABLE IF NOT EXISTS audit_reports (
        report_id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        engine_version TEXT NOT NULL,
        checklist_version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        report_hash TEXT NOT NULL,
        signature TEXT,
        public_key TEXT,
        status TEXT NOT NULL DEFAULT 'VALID', -- 'VALID' | 'REVOKED' | 'INVALID'
        canonical_payload_json TEXT NOT NULL,
        revoked_at TEXT,
        revocation_reason TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS pilot_telemetry_events (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        org_id TEXT NOT NULL,
        user_id TEXT,
        device_id TEXT,
        details_json TEXT,
        timestamp TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS endpoints (
        endpoint_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        machine_uuid TEXT,
        device_type TEXT NOT NULL,
        platform TEXT NOT NULL,
        architecture TEXT NOT NULL,
        runtime_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        FOREIGN KEY (org_id) REFERENCES organizations(org_id),
        FOREIGN KEY (device_id) REFERENCES devices(device_id)
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_org_device ON endpoints(org_id, device_id);

      CREATE TABLE IF NOT EXISTS endpoint_assessments (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT,
        org_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        platform TEXT NOT NULL,
        device_type TEXT,
        runtime_type TEXT,
        detection_source TEXT,
        hostname TEXT,
        machine_uuid TEXT,
        application_version TEXT NOT NULL,
        agent_version TEXT,
        overall_status TEXT NOT NULL,
        evidence_hash TEXT,
        provenance_json TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id),
        FOREIGN KEY (device_id) REFERENCES devices(device_id)
      );

      CREATE TABLE IF NOT EXISTS endpoint_detection_results (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        category TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence TEXT NOT NULL,
        detection_method TEXT NOT NULL,
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES endpoint_assessments(id)
      );

      CREATE TABLE IF NOT EXISTS clock_drift_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        delta_ms INTEGER NOT NULL,
        elapsed_performance_ms REAL NOT NULL,
        elapsed_date_ms INTEGER NOT NULL,
        status TEXT NOT NULL
      );
    `);

    // Database schema migrations for existing databases
    try {
      const sessionCols = db.prepare("PRAGMA table_info(audit_sessions)").all() as { name: string }[];
      if (!sessionCols.some(c => c.name === 'scan_id')) {
        db.exec("ALTER TABLE audit_sessions ADD COLUMN scan_id TEXT;");
      }
      if (!sessionCols.some(c => c.name === 'org_id')) {
        db.exec("ALTER TABLE audit_sessions ADD COLUMN org_id TEXT;");
      }
      if (!sessionCols.some(c => c.name === 'user_id')) {
        db.exec("ALTER TABLE audit_sessions ADD COLUMN user_id TEXT;");
      }
      if (!sessionCols.some(c => c.name === 'device_id')) {
        db.exec("ALTER TABLE audit_sessions ADD COLUMN device_id TEXT;");
      }

      const scanCols = db.prepare("PRAGMA table_info(scans)").all() as { name: string }[];
      if (!scanCols.some(c => c.name === 'org_id')) {
        db.exec("ALTER TABLE scans ADD COLUMN org_id TEXT;");
      }
      if (!scanCols.some(c => c.name === 'user_id')) {
        db.exec("ALTER TABLE scans ADD COLUMN user_id TEXT;");
      }
      if (!scanCols.some(c => c.name === 'device_id')) {
        db.exec("ALTER TABLE scans ADD COLUMN device_id TEXT;");
      }
      if (!scanCols.some(c => c.name === 'endpoint_id')) {
        db.exec("ALTER TABLE scans ADD COLUMN endpoint_id TEXT;");
      }
      if (!scanCols.some(c => c.name === 'detection_source')) {
        db.exec("ALTER TABLE scans ADD COLUMN detection_source TEXT;");
      }
      if (!scanCols.some(c => c.name === 'runtime_type')) {
        db.exec("ALTER TABLE scans ADD COLUMN runtime_type TEXT;");
      }

      const epAssessmentCols = db.prepare("PRAGMA table_info(endpoint_assessments)").all() as { name: string }[];
      if (!epAssessmentCols.some(c => c.name === 'endpoint_id')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN endpoint_id TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'runtime_type')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN runtime_type TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'detection_source')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN detection_source TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'device_type')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN device_type TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'hostname')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN hostname TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'machine_uuid')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN machine_uuid TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'agent_version')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN agent_version TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'started_at')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN started_at TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'completed_at')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN completed_at TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'evidence_hash')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN evidence_hash TEXT;");
      }
      if (!epAssessmentCols.some(c => c.name === 'provenance_json')) {
        db.exec("ALTER TABLE endpoint_assessments ADD COLUMN provenance_json TEXT;");
      }

      const orgCols = db.prepare("PRAGMA table_info(organizations)").all() as { name: string }[];
      if (!orgCols.some(c => c.name === 'suspended')) {
        db.exec("ALTER TABLE organizations ADD COLUMN suspended INTEGER DEFAULT 0;");
      }

      const licCols = db.prepare("PRAGMA table_info(licenses)").all() as { name: string }[];
      if (!licCols.some(c => c.name === 'trial_start')) {
        db.exec("ALTER TABLE licenses ADD COLUMN trial_start TEXT;");
      }
      if (!licCols.some(c => c.name === 'trial_end')) {
        db.exec("ALTER TABLE licenses ADD COLUMN trial_end TEXT;");
      }
      if (!licCols.some(c => c.name === 'trial_status')) {
        db.exec("ALTER TABLE licenses ADD COLUMN trial_status TEXT;");
      }

      const reportCols = db.prepare("PRAGMA table_info(audit_reports)").all() as { name: string }[];
      if (reportCols.length > 0) {
        if (!reportCols.some(c => c.name === 'signature')) {
          db.exec("ALTER TABLE audit_reports ADD COLUMN signature TEXT;");
        }
        if (!reportCols.some(c => c.name === 'public_key')) {
          db.exec("ALTER TABLE audit_reports ADD COLUMN public_key TEXT;");
        }
      }
    } catch (migErr) {
      console.warn('[DB Migration] migration check:', migErr);
    }

    // Seed default system administrator if none exists
    const sysAdminCheck = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'SYS_ADMIN'").get() as { count: number };
    if (sysAdminCheck.count === 0) {
      const sysOrgId = 'org-sysadmin-internal';
      const now = new Date().toISOString();
      db.prepare('INSERT OR IGNORE INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run(sysOrgId, 'FileSentinel Internal Administration', now);

      const sysUserId = 'user-sysadmin-01';
      const saltBuf = crypto.randomBytes(16);
      const passBuf = Buffer.from('SysAdmin123!', 'utf8');
      const hashBuf = crypto.scryptSync(passBuf, saltBuf, 64);
      const sysHash = `${saltBuf.toString('hex')}:${hashBuf.toString('hex')}`;
      db.prepare('INSERT OR IGNORE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(sysUserId, sysOrgId, 'sysadmin', sysHash, 'SYS_ADMIN', now);
    }

    // Seed default plans
    const planCheck = db.prepare('SELECT COUNT(*) as count FROM plans').get() as { count: number };
    if (planCheck.count === 0) {
      const now = new Date().toISOString();
      const insertPlan = db.prepare(`
        INSERT INTO plans (plan_id, name, max_users, max_devices, scan_limit, feature_flags, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      insertPlan.run(
        'plan-starter-trial',
        'Starter Trial',
        2,
        2,
        25,
        JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE']),
        now
      );
      insertPlan.run(
        'plan-professional',
        'Professional',
        10,
        10,
        500,
        JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING']),
        now
      );
      insertPlan.run(
        'plan-enterprise',
        'Enterprise Suite',
        100,
        50,
        -1,
        JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CLOUD_EVIDENCE_UPLOAD', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING', 'API_ACCESS']),
        now
      );
    }

    // Seed default organization, user, device, and license if devadmin does not exist (dev mode only)
    if (process.env.NODE_ENV !== 'production') {
      const devAdminCheck = db.prepare("SELECT COUNT(*) as count FROM users WHERE username = 'devadmin'").get() as { count: number };
      if (devAdminCheck.count === 0) {
        const defaultOrgId = 'org-default-dev';
        const now = new Date().toISOString();
        db.prepare('INSERT OR IGNORE INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(defaultOrgId, 'Default Dev Organization', now);

        const defaultUserId = 'user-default-dev';
        const saltBuf = crypto.randomBytes(16);
        const passBuf = Buffer.from('devpassword', 'utf8');
        const hashBuf = crypto.scryptSync(passBuf, saltBuf, 64);
        const defaultHash = `${saltBuf.toString('hex')}:${hashBuf.toString('hex')}`;
        db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(defaultUserId, defaultOrgId, 'devadmin', defaultHash, 'ORG_ADMIN', now);

        const defaultDeviceId = 'dev-device-default';
        db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(defaultDeviceId, defaultOrgId, 'Default Development Device', now);

        // Seed default active enterprise license for dev organization
        const defaultLicenseId = 'lic-default-dev';
        const startsAt = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
        const expiresAt = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
        const graceUntil = new Date(Date.now() + (365 + 7) * 24 * 3600 * 1000).toISOString();
        const enterpriseFeatures = JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CLOUD_EVIDENCE_UPLOAD', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING', 'API_ACCESS']);

        db.prepare(`
          INSERT INTO licenses (
            license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
            grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
            created_at, updated_at, last_validated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        `).run(
          defaultLicenseId,
          defaultOrgId,
          'plan-enterprise',
          'ACTIVE',
          now,
          startsAt,
          expiresAt,
          graceUntil,
          100,
          50,
          -1,
          enterpriseFeatures,
          now,
          now,
          now
        );

        // Activate default device on the license
        db.prepare(`
          INSERT INTO license_devices (id, license_id, device_id, activated_at, status, last_seen_at)
          VALUES (?, ?, ?, ?, 'ACTIVE', ?)
        `).run('ldev-default-dev', defaultLicenseId, defaultDeviceId, now, now);
      }
    }

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

  let instance: DatabaseSync;
  try {
    instance = initDb(dbPath);
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
      instance = initDb(dbPath);
    } else {
      throw err;
    }
  }

  if (dbPath === './filesentinel.db') {
    defaultDbInstance = instance;
  }

  return instance;
}
