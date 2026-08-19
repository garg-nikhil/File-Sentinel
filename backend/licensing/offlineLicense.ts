import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../db.js';
import { ProtectedLicenseStore, ProtectedLicenseState } from './protectedLicenseStore.js';

export interface LicenseLeasePayload {
  licenseId: string;
  organizationId: string;
  deviceLimit: number;
  modules: string[];
  issuedAt: string;
  notBefore: string;
  expiresAt: string;
  licenseVersion: string;
  boundDeviceId?: string;
  boundMachineUuid?: string;
  issuer?: string;
  product?: string;
}

export interface SignedLicenseLease {
  payload: LicenseLeasePayload;
  signature: string; // Base64 signature
  publicKeyId: string;
}

export type OfflineLicenseStatus =
  | 'ACTIVE'
  | 'WARNING_7D'
  | 'WARNING_3D'
  | 'WARNING_1D'
  | 'GRACE_PERIOD'
  | 'EXPIRED'
  | 'REVOKED'
  | 'INVALID_SIGNATURE'
  | 'DEVICE_MISMATCH'
  | 'ORG_MISMATCH'
  | 'CLOCK_ROLLBACK_DETECTED'
  | 'NOT_YET_VALID';

export interface OfflineValidationResult {
  valid: boolean;
  status: OfflineLicenseStatus;
  canScan: boolean;
  canAudit: boolean;
  isGracePeriod: boolean;
  daysRemaining: number;
  hoursRemaining: number;
  message: string;
  lease?: LicenseLeasePayload;
  clockRollbackDetected?: boolean;
}

// Built-in FileSentinel Root Public Keys for offline asymmetric verification (Ed25519)
export const TRUSTED_PUBLIC_KEYS: Record<string, string> = {
  'fs-root-2026': `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4P2z6N7FhHq8yXq0l8+0eI4XbZqVl5m8pZ1n5xZ3d8A=
-----END PUBLIC KEY-----`,
  'fs-test-key': '' // Will be generated or dynamically bound for tests
};

// Keypair for self-signed development/test leases
let devKeyPair: { publicKey: string; privateKey: string } | null = null;

export function getOrCreateDevKeyPair(): { publicKey: string; privateKey: string } {
  if (!devKeyPair) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    devKeyPair = { publicKey, privateKey };
    TRUSTED_PUBLIC_KEYS['fs-dev-key'] = publicKey;
  }
  return devKeyPair;
}

export class OfflineLicenseEngine {
  private db: DatabaseSync;
  private defaultGracePeriodDays: number;
  private clockRollbackToleranceMs: number;

  constructor(db?: DatabaseSync, gracePeriodDays: number = 3, rollbackToleranceMs: number = 3600 * 1000) {
    this.db = db || getDatabase();
    this.defaultGracePeriodDays = gracePeriodDays;
    this.clockRollbackToleranceMs = rollbackToleranceMs;
    this.ensureTables();
  }

  public validateCurrentLicense(context: {
    orgId: string;
    deviceId?: string;
    machineUuid?: string;
    currentTime?: Date;
    protectedStorePath?: string;
  }): OfflineValidationResult {
    // 1. Try to load from ProtectedLicenseStore
    const protectedStore = new ProtectedLicenseStore(context.protectedStorePath);
    const protectedState = protectedStore.loadState();
    if (protectedState && protectedState.signedLeaseJson) {
      try {
        const signedLease = JSON.parse(protectedState.signedLeaseJson) as SignedLicenseLease;
        return this.validateLease(signedLease, context);
      } catch {}
    }

    // 2. Fallback to license_state SQLite table
    try {
      const row = this.db.prepare(
        'SELECT lease_jwt FROM license_state WHERE org_id = ? ORDER BY updated_at DESC LIMIT 1'
      ).get(context.orgId) as { lease_jwt: string } | undefined;

      if (row && row.lease_jwt) {
        const signedLease = JSON.parse(row.lease_jwt) as SignedLicenseLease;
        return this.validateLease(signedLease, context);
      }
    } catch {}

    // No valid lease stored
    return {
      valid: false,
      status: 'EXPIRED',
      canScan: false,
      canAudit: false,
      isGracePeriod: false,
      daysRemaining: 0,
      hoursRemaining: 0,
      message: 'No commercial offline license lease found. Please upload a valid cloud-issued signed license lease.'
    };
  }

  private ensureTables(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS license_state (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL,
          license_id TEXT NOT NULL,
          lease_jwt TEXT,
          license_version TEXT NOT NULL,
          device_limit INTEGER NOT NULL,
          modules_json TEXT NOT NULL,
          issued_at TEXT NOT NULL,
          not_before TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          grace_until TEXT NOT NULL,
          last_trusted_timestamp TEXT NOT NULL,
          clock_rollback_detected INTEGER DEFAULT 0,
          last_online_validation_at TEXT,
          status TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY (org_id) REFERENCES organizations(org_id)
        );
      `);
    } catch {}
  }

  /**
   * Helper to compare version strings (e.g. "1.0", "8.2.0")
   */
  public static compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split(/[.-]/).map(x => parseInt(x, 10) || 0);
    const parts2 = v2.split(/[.-]/).map(x => parseInt(x, 10) || 0);
    const len = Math.max(parts1.length, parts2.length);
    for (let i = 0; i < len; i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;
      if (p1 !== p2) return p1 - p2;
    }
    return 0;
  }

  /**
   * Server-side helper to sign a lease payload with a private key
   */
  public static signLease(payload: LicenseLeasePayload, privateKeyPem: string, keyId: string = 'fs-dev-key'): SignedLicenseLease {
    const canonicalString = JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuf = Buffer.from(canonicalString, 'utf8');
    const privateKeyBuf = Buffer.from(privateKeyPem, 'utf8');
    const signature = crypto.sign(null, dataBuf, privateKeyBuf).toString('base64');

    // Securely overwrite the transient private key buffer
    privateKeyBuf.fill(0);

    return {
      payload,
      signature,
      publicKeyId: keyId
    };
  }

  /**
   * Cryptographically verify the signed lease with the matching public key
   */
  public static verifySignature(signedLease: SignedLicenseLease, customPublicKeyPem?: string): boolean {
    try {
      const isProduction = process.env.NODE_ENV === 'production';
      let pubKey: string | undefined;

      if (isProduction) {
        // Strict production verification: MUST use fs-root-2026 public key
        if (signedLease.publicKeyId !== 'fs-root-2026') {
          return false;
        }
        pubKey = TRUSTED_PUBLIC_KEYS['fs-root-2026'];
      } else {
        // Non-production or test mode can use custom keys only if they are mapped or passed
        if (customPublicKeyPem) {
          const isTrusted = Object.values(TRUSTED_PUBLIC_KEYS).some(
            k => k && k.replace(/\s+/g, '') === customPublicKeyPem.replace(/\s+/g, '')
          );
          if (!isTrusted) {
            return false; // Reject mathematically valid signature from untrusted key!
          }
          pubKey = customPublicKeyPem;
        } else {
          pubKey = TRUSTED_PUBLIC_KEYS[signedLease.publicKeyId];
        }
      }

      if (!pubKey) return false;

      const canonicalString = JSON.stringify(signedLease.payload, Object.keys(signedLease.payload).sort());
      const dataBuf = Buffer.from(canonicalString, 'utf8');
      const sigBuf = Buffer.from(signedLease.signature, 'base64');
      const verified = crypto.verify(null, dataBuf, pubKey, sigBuf);

      // Never attempt to zero public keys!

      return verified;
    } catch {
      return false;
    }
  }

  /**
   * Validate license lease offline against organization, device, and temporal constraints
   */
  public validateLease(
    signedLease: SignedLicenseLease,
    context: {
      orgId: string;
      deviceId?: string;
      machineUuid?: string;
      currentTime?: Date;
      publicKeyPem?: string;
      protectedStorePath?: string;
    }
  ): OfflineValidationResult {
    const now = context.currentTime || new Date();
    const nowIso = now.toISOString();
    const nowMs = now.getTime();

    // 1. Cryptographic Signature Verification
    const isSigValid = OfflineLicenseEngine.verifySignature(signedLease, context.publicKeyPem);
    if (!isSigValid) {
      return {
        valid: false,
        status: 'INVALID_SIGNATURE',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: 'Cryptographic license signature verification failed or key is untrusted.',
        lease: signedLease.payload
      };
    }

    const payload = signedLease.payload;

    // 2. Product and Organization ID Check
    if (payload.product && payload.product !== 'FileSentinel') {
      return {
        valid: false,
        status: 'PRODUCT_MISMATCH' as any,
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: `License is bound to product '${payload.product}', not 'FileSentinel'.`,
        lease: payload
      };
    }

    if (payload.organizationId !== context.orgId) {
      return {
        valid: false,
        status: 'ORG_MISMATCH',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: `License is bound to organization '${payload.organizationId}', not '${context.orgId}'.`,
        lease: payload
      };
    }

    // 3. Device Binding Check (if specified in lease)
    if (payload.boundDeviceId && context.deviceId && payload.boundDeviceId !== context.deviceId) {
      return {
        valid: false,
        status: 'DEVICE_MISMATCH',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: `License is bound to device '${payload.boundDeviceId}', not '${context.deviceId}'.`,
        lease: payload
      };
    }

    // 4. Temporal Check: Not Before
    const notBeforeMs = new Date(payload.notBefore).getTime();
    if (nowMs < notBeforeMs) {
      return {
        valid: false,
        status: 'NOT_YET_VALID',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: `License is not valid until ${payload.notBefore}.`,
        lease: payload
      };
    }

    // 5. OS-Protected Persistent Store Validation (Anti-DB Reset & Hardware Binding)
    const protectedStore = new ProtectedLicenseStore(context.protectedStorePath);
    const protectedState = protectedStore.loadState();
    const currentMachineFp = ProtectedLicenseStore.getMachineFingerprint();

    // Stale/Replay Check:
    // If we have an existing persistent state (from OS file or DB) for this specific license
    let maxSeenIssuedAtMs = 0;
    let maxSeenVersionStr = '0.0.0';

    if (protectedState && protectedState.licenseId === payload.licenseId) {
      if (protectedState.maxSeenIssuedAtIso) {
        maxSeenIssuedAtMs = new Date(protectedState.maxSeenIssuedAtIso).getTime();
      }
      if (protectedState.maxSeenVersion) {
        maxSeenVersionStr = protectedState.maxSeenVersion;
      }
    }

    // Also parse other leases stored in DB for this specific license to find max seen
    try {
      const dbRows = this.db.prepare('SELECT lease_jwt FROM license_state WHERE org_id = ? AND license_id = ?').all(context.orgId, payload.licenseId) as { lease_jwt: string }[];
      for (const row of dbRows) {
        if (row.lease_jwt) {
          const storedLease = JSON.parse(row.lease_jwt) as SignedLicenseLease;
          if (storedLease && storedLease.payload && storedLease.payload.licenseId === payload.licenseId) {
            const issuedMs = new Date(storedLease.payload.issuedAt).getTime();
            if (!isNaN(issuedMs) && issuedMs > maxSeenIssuedAtMs) {
              maxSeenIssuedAtMs = issuedMs;
            }
            if (storedLease.payload.licenseVersion && OfflineLicenseEngine.compareVersions(storedLease.payload.licenseVersion, maxSeenVersionStr) > 0) {
              maxSeenVersionStr = storedLease.payload.licenseVersion;
            }
          }
        }
      }
    } catch {}

    const incomingIssuedMs = new Date(payload.issuedAt).getTime();
    if (!isNaN(incomingIssuedMs) && maxSeenIssuedAtMs > 0 && incomingIssuedMs < maxSeenIssuedAtMs) {
      return {
        valid: false,
        status: 'EXPIRED',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: 'Rejecting stale or replayed license lease with an older issue date.',
        lease: payload
      };
    }

    if (payload.licenseVersion && maxSeenVersionStr !== '0.0.0' && OfflineLicenseEngine.compareVersions(payload.licenseVersion, maxSeenVersionStr) < 0) {
      return {
        valid: false,
        status: 'EXPIRED',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        message: 'Rejecting stale or replayed license lease with a lower version.',
        lease: payload
      };
    }

    const isNewRevalidation = (payload.licenseVersion && maxSeenVersionStr !== '0.0.0' && OfflineLicenseEngine.compareVersions(payload.licenseVersion, maxSeenVersionStr) > 0) ||
                             (!isNaN(incomingIssuedMs) && maxSeenIssuedAtMs > 0 && incomingIssuedMs > maxSeenIssuedAtMs);

    // Let's check wall-clock rollback across restart, DB restoration, and application restart.
    let clockRollbackDetected = false;
    let dbRestorationDetected = false;

    if (protectedState) {
      // Hardware/VM Cloning Check
      if (protectedState.machineFingerprint && protectedState.machineFingerprint !== currentMachineFp) {
        return {
          valid: false,
          status: 'DEVICE_MISMATCH',
          canScan: false,
          canAudit: false,
          isGracePeriod: false,
          daysRemaining: 0,
          hoursRemaining: 0,
          message: 'License is bound to a different machine hardware fingerprint. Cloned environment detected.',
          lease: payload
        };
      }

      // Check for persistent rollback or inconsistent state from previous run
      if (protectedState.clockRollbackDetected || protectedState.status === 'CLOCK_ROLLBACK_DETECTED') {
        if (!isNewRevalidation) {
          clockRollbackDetected = true;
        }
      }

      // Check Monotonic Progression from OS-Protected Store
      const fileMaxMs = new Date(protectedState.maxSeenTimestampIso).getTime();
      if (!isNaN(fileMaxMs) && nowMs < (fileMaxMs - this.clockRollbackToleranceMs)) {
        if (!isNewRevalidation) {
          clockRollbackDetected = true;
        }
      }
    }

    // SQLite Clock Rollback Protection Check & DB Restoration Attack Check
    try {
      const dbRow = this.db.prepare(
        'SELECT last_trusted_timestamp, clock_rollback_detected FROM license_state WHERE org_id = ? ORDER BY last_trusted_timestamp DESC LIMIT 1'
      ).get(context.orgId) as { last_trusted_timestamp: string; clock_rollback_detected: number } | undefined;

      if (dbRow && dbRow.last_trusted_timestamp) {
        const dbMaxMs = new Date(dbRow.last_trusted_timestamp).getTime();
        if (!isNaN(dbMaxMs)) {
          if (nowMs < (dbMaxMs - this.clockRollbackToleranceMs)) {
            if (!isNewRevalidation) {
              clockRollbackDetected = true;
            }
          }
          // Detect DB restoration / backup rollback:
          // If the persistent store file's trusted timestamp is significantly ahead of the database's trusted timestamp,
          // it indicates the database has been restored to an older state!
          if (protectedState && protectedState.maxSeenTimestampIso) {
            const fileMaxMs = new Date(protectedState.maxSeenTimestampIso).getTime();
            if (!isNaN(fileMaxMs) && dbMaxMs < (fileMaxMs - 24 * 3600 * 1000)) { // say 1 day out of sync
              if (!isNewRevalidation) {
                dbRestorationDetected = true;
              }
            }
          }
        }
        if (dbRow.clock_rollback_detected === 1) {
          if (!isNewRevalidation) {
            clockRollbackDetected = true;
          }
        }
      }
    } catch {}

    if (clockRollbackDetected || dbRestorationDetected) {
      // Inconsistency detected!
      if (protectedState) {
        protectedStore.saveState({
          ...protectedState,
          clockRollbackDetected: true,
          status: 'CLOCK_ROLLBACK_DETECTED',
          updatedAtIso: nowIso
        });
      }

      try {
        this.db.prepare(
          'UPDATE license_state SET clock_rollback_detected = 1, status = ?, updated_at = ? WHERE org_id = ?'
        ).run('CLOCK_ROLLBACK_DETECTED', nowIso, context.orgId);
      } catch {}

      return {
        valid: false,
        status: 'CLOCK_ROLLBACK_DETECTED',
        canScan: false,
        canAudit: false,
        isGracePeriod: false,
        daysRemaining: 0,
        hoursRemaining: 0,
        clockRollbackDetected: true,
        message: dbRestorationDetected
          ? 'Inconsistent trusted-time state detected (possible database restoration). Scanning is blocked. Online re-validation is required.'
          : 'System clock tampering or rollback detected. Scanning is blocked. Online re-validation is required.',
        lease: payload
      };
    }

    // 6. Expiration & Grace Period Calculation
    const expiresAtMs = new Date(payload.expiresAt).getTime();
    const graceUntilMs = expiresAtMs + (this.defaultGracePeriodDays * 86400 * 1000);
    const msRemaining = expiresAtMs - nowMs;
    const daysRemaining = Math.ceil(msRemaining / (86400 * 1000));
    const hoursRemaining = Math.max(0, Math.ceil(msRemaining / (3600 * 1000)));

    let status: OfflineLicenseStatus = 'ACTIVE';
    let canScan = true;
    let canAudit = true;
    let isGracePeriod = false;
    let message = 'License active and valid.';

    if (nowMs > graceUntilMs) {
      status = 'EXPIRED';
      canScan = false;
      canAudit = false;
      message = `Subscription expired on ${payload.expiresAt}. Scan and audit operations are blocked.`;
    } else if (nowMs > expiresAtMs) {
      status = 'GRACE_PERIOD';
      canScan = true;
      canAudit = true;
      isGracePeriod = true;
      const graceHoursLeft = Math.ceil((graceUntilMs - nowMs) / (3600 * 1000));
      message = `Subscription expired. In grace period (${graceHoursLeft} hours remaining). Please renew your license.`;
    } else if (daysRemaining <= 1) {
      status = 'WARNING_1D';
      message = `Subscription expires in ${hoursRemaining} hours (tomorrow). Please renew.`;
    } else if (daysRemaining <= 3) {
      status = 'WARNING_3D';
      message = `Subscription expires in ${daysRemaining} days. Please renew.`;
    } else if (daysRemaining <= 7) {
      status = 'WARNING_7D';
      message = `Subscription expires in ${daysRemaining} days.`;
    }

    // 7. Update trusted timestamp & persistent state in OS-Protected Store and SQLite
    const stateRow = this.db.prepare(
      'SELECT last_trusted_timestamp FROM license_state WHERE org_id = ? AND license_id = ?'
    ).get(context.orgId, payload.licenseId) as { last_trusted_timestamp: string } | undefined;

    const currentTrusted = stateRow?.last_trusted_timestamp
      ? (new Date(stateRow.last_trusted_timestamp).getTime() > nowMs ? stateRow.last_trusted_timestamp : nowIso)
      : nowIso;

    const prevMaxMs = protectedState?.maxSeenTimestampIso ? new Date(protectedState.maxSeenTimestampIso).getTime() : 0;
    const newMaxIso = nowMs > prevMaxMs ? nowIso : (protectedState?.maxSeenTimestampIso || nowIso);

    // Track the highest version and issuedAt
    const updatedMaxSeenVersion = (protectedState?.maxSeenVersion && OfflineLicenseEngine.compareVersions(protectedState.maxSeenVersion, payload.licenseVersion) > 0)
      ? protectedState.maxSeenVersion
      : payload.licenseVersion;

    const updatedMaxSeenIssuedAtIso = (protectedState?.maxSeenIssuedAtIso && new Date(protectedState.maxSeenIssuedAtIso).getTime() > new Date(payload.issuedAt).getTime())
      ? protectedState.maxSeenIssuedAtIso
      : payload.issuedAt;

    protectedStore.saveState({
      organizationId: context.orgId,
      licenseId: payload.licenseId,
      signedLeaseJson: JSON.stringify(signedLease),
      machineFingerprint: currentMachineFp,
      maxSeenTimestampIso: newMaxIso,
      lastTrustedTimestampIso: currentTrusted,
      status,
      graceUntilIso: new Date(graceUntilMs).toISOString(),
      expiresAtIso: payload.expiresAt,
      clockRollbackDetected: false,
      updatedAtIso: nowIso,
      maxSeenVersion: updatedMaxSeenVersion,
      maxSeenIssuedAtIso: updatedMaxSeenIssuedAtIso
    });

    this.db.prepare(`
      INSERT INTO license_state (
        id, org_id, license_id, lease_jwt, license_version, device_limit,
        modules_json, issued_at, not_before, expires_at, grace_until,
        last_trusted_timestamp, clock_rollback_detected, status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        lease_jwt = excluded.lease_jwt,
        expires_at = excluded.expires_at,
        grace_until = excluded.grace_until,
        last_trusted_timestamp = excluded.last_trusted_timestamp,
        status = excluded.status,
        updated_at = excluded.updated_at
    `).run(
      `lic-state-${context.orgId}-${payload.licenseId}`,
      context.orgId,
      payload.licenseId,
      JSON.stringify(signedLease),
      payload.licenseVersion || '1.0',
      payload.deviceLimit,
      JSON.stringify(payload.modules || []),
      payload.issuedAt,
      payload.notBefore,
      payload.expiresAt,
      new Date(graceUntilMs).toISOString(),
      currentTrusted,
      status,
      nowIso
    );

    return {
      valid: (status as OfflineLicenseStatus) !== 'EXPIRED' && (status as OfflineLicenseStatus) !== 'CLOCK_ROLLBACK_DETECTED',
      status,
      canScan,
      canAudit,
      isGracePeriod,
      daysRemaining,
      hoursRemaining,
      message,
      lease: payload
    };
  }
}
