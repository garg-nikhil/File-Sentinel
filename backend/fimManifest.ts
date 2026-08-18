import crypto from 'node:crypto';

export interface FimManifestPayload {
  version: string;
  issuedAt: string;
  files: Record<string, string>;
}

export interface SignedFimManifest {
  payload: FimManifestPayload;
  signature: string;
}

// Manufacturer signing secret anchor embedded into the build artifact
export const MANUFACTURER_FIM_SIGNING_KEY = 'FILE_SENTINEL_MANUFACTURER_SIGNING_KEY_BUILD_2026_V8';

/**
 * Signs a FIM manifest payload with the manufacturer signing key
 */
export function signFimManifest(payload: FimManifestPayload, key: string = MANUFACTURER_FIM_SIGNING_KEY): SignedFimManifest {
  const serialized = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', key).update(serialized, 'utf8').digest('hex');
  return { payload, signature };
}

/**
 * Verifies a signed FIM manifest against the manufacturer anchor
 */
export function verifySignedFimManifest(manifest: SignedFimManifest, key: string = MANUFACTURER_FIM_SIGNING_KEY): boolean {
  if (!manifest || !manifest.payload || !manifest.signature) return false;
  try {
    const serialized = JSON.stringify(manifest.payload);
    const expected = crypto.createHmac('sha256', key).update(serialized, 'utf8').digest('hex');
    return crypto.timingSafeEqual(Buffer.from(manifest.signature, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

// Default Manufacturer-Signed Embedded Baseline Manifest
export const EMBEDDED_MANUFACTURER_MANIFEST: SignedFimManifest = signFimManifest({
  version: '8.2.0-rc1',
  issuedAt: '2026-08-18T00:00:00.000Z',
  files: {
    'backend/auth.ts': 'EMBEDDED_SIGNATURE_AUTH_V8',
    'backend/licensing.ts': 'EMBEDDED_SIGNATURE_LIC_V8',
    'backend/db.ts': 'EMBEDDED_SIGNATURE_DB_V8',
    'backend/routes.ts': 'EMBEDDED_SIGNATURE_ROUTES_V8',
    'backend/securityMiddleware.ts': 'EMBEDDED_SIGNATURE_SEC_V8',
    'backend/audit/verifiableReportService.ts': 'EMBEDDED_SIGNATURE_AUDIT_V8'
  }
});
