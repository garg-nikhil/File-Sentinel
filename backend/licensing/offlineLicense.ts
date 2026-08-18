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
   * Server-side helper to sign a lease payload with a private key
   */
  public static signLease(payload: LicenseLeasePayload, privateKeyPem: string, keyId: string = 'fs-dev-key'): SignedLicenseLease {
    const canonicalString = JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuf = Buffer.from(canonicalString, 'utf8');
    const signature = crypto.sign(null, dataBuf, privateKeyPem).toString('base64');

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
      const pubKey = customPublicKeyPem || TRUSTED_PUBLIC_KEYS[signedLease.publicKeyId];
      if (!pubKey) return false;

      const canonicalString = JSON.stringify(signedLease.payload, Object.keys(signedLease.payload).sort());
      const dataBuf = Buffer.from(canonicalString, 'utf8');
      const sigBuf = Buffer.from(signedLease.signature, 'base64');
      return crypto.verify(null, dataBuf, pubKey, sigBuf);
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

    // 2. Organization ID Check
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

      // SQLite Reset / DB Restoration Attack Check
      if (protectedState.clockRollbackDetected || protectedState.status === 'CLOCK_ROLLBACK_DETECTED') {
        return {
          valid: false,
          status: 'CLOCK_ROLLBACK_DETECTED',
          canScan: false,
          canAudit: false,
          isGracePeriod: false,
          daysRemaining: 0,
          hoursRemaining: 0,
          clockRollbackDetected: true,
          message: 'Persistent clock rollback detected in OS-protected license store.',
          lease: payload
        };
      }

      // Check Monotonic Progression from OS-Protected Store
      const protectedMaxMs = new Date(protectedState.maxSeenTimestampIso).getTime();
      if (!isNaN(protectedMaxMs) && nowMs < (protectedMaxMs - this.clockRollbackToleranceMs)) {
        protectedStore.saveState({
          ...protectedState,
          clockRollbackDetected: true,
          status: 'CLOCK_ROLLBACK_DETECTED',
          updatedAtIso: nowIso
        });

        return {
          valid: false,
          status: 'CLOCK_ROLLBACK_DETECTED',
          canScan: false,
          canAudit: false,
          isGracePeriod: false,
          daysRemaining: 0,
          hoursRemaining: 0,
          clockRollbackDetected: true,
          message: 'System clock tampering or rollback detected via OS-protected license store. Online re-validation required.',
          lease: payload
        };
      }
    }

    // 6. SQLite Clock Rollback Protection Check
    const stateRow = this.db.prepare(
      'SELECT last_trusted_timestamp, clock_rollback_detected FROM license_state WHERE org_id = ? AND license_id = ?'
    ).get(context.orgId, payload.licenseId) as { last_trusted_timestamp: string; clock_rollback_detected: number } | undefined;

    let clockRollback = false;
    if (stateRow && stateRow.last_trusted_timestamp) {
      const lastTrustedMs = new Date(stateRow.last_trusted_timestamp).getTime();
      if (nowMs < (lastTrustedMs - this.clockRollbackToleranceMs)) {
        clockRollback = true;
        this.db.prepare(
          'UPDATE license_state SET clock_rollback_detected = 1, status = ?, updated_at = ? WHERE org_id = ? AND license_id = ?'
        ).run('CLOCK_ROLLBACK_DETECTED', nowIso, context.orgId, payload.licenseId);

        return {
          valid: false,
          status: 'CLOCK_ROLLBACK_DETECTED',
          canScan: false,
          canAudit: false,
          isGracePeriod: false,
          daysRemaining: 0,
          hoursRemaining: 0,
          clockRollbackDetected: true,
          message: 'System clock tampering or rollback detected. Online re-validation required.',
          lease: payload
        };
      }
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
    const currentTrusted = stateRow?.last_trusted_timestamp
      ? (new Date(stateRow.last_trusted_timestamp).getTime() > nowMs ? stateRow.last_trusted_timestamp : nowIso)
      : nowIso;

    const prevMaxMs = protectedState?.maxSeenTimestampIso ? new Date(protectedState.maxSeenTimestampIso).getTime() : 0;
    const newMaxIso = nowMs > prevMaxMs ? nowIso : (protectedState?.maxSeenTimestampIso || nowIso);

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
      updatedAtIso: nowIso
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
