import crypto from 'node:crypto';

export interface FimManifestPayload {
  version: string;
  issuedAt: string;
  files: Record<string, string>;
}

export interface SignedFimManifest {
  payload: FimManifestPayload;
  signature: string; // Base64 encoded Ed25519 signature
  publicKeyId?: string;
}

// Official FileSentinel Manufacturer Ed25519 Public Key (Public Key ONLY in app)
export const TRUSTED_FIM_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARUgVlL6uKL9q+WIHNeK5gALNu47hP6pceXcX+deA0wk=
-----END PUBLIC KEY-----`;

/**
 * Signs a FIM manifest payload with an Ed25519 private key (Build/Release environment only).
 */
export function signFimManifest(payload: FimManifestPayload, privateKeyPem: string): SignedFimManifest {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const dataBuf = Buffer.from(canonical, 'utf8');
  const privateKeyBuf = Buffer.from(privateKeyPem, 'utf8');
  const signature = crypto.sign(null, dataBuf, privateKeyBuf).toString('base64');
  privateKeyBuf.fill(0);
  return { payload, signature, publicKeyId: 'fs-fim-root-2026' };
}

/**
 * Cryptographically verifies a signed FIM manifest against the official Ed25519 public key.
 */
export function verifySignedFimManifest(manifest: SignedFimManifest, publicKeyPem: string = TRUSTED_FIM_PUBLIC_KEY): boolean {
  if (!manifest || !manifest.payload || !manifest.signature) return false;
  try {
    const canonical = JSON.stringify(manifest.payload, Object.keys(manifest.payload).sort());
    const dataBuf = Buffer.from(canonical, 'utf8');
    const sigBuf = Buffer.from(manifest.signature, 'base64');
    return crypto.verify(null, dataBuf, publicKeyPem, sigBuf);
  } catch {
    return false;
  }
}

// Initial immutable baseline manifest payload signed with official manufacturer Ed25519 key
export const EMBEDDED_MANUFACTURER_MANIFEST: SignedFimManifest = {
  payload: {
    version: '8.2.0-rc1',
    issuedAt: '2026-08-18T00:00:00.000Z',
    files: {
      'backend/auth.ts': 'EMBEDDED_ANCHOR',
      'backend/licensing.ts': 'EMBEDDED_ANCHOR',
      'backend/db.ts': 'EMBEDDED_ANCHOR',
      'backend/routes.ts': 'EMBEDDED_ANCHOR',
      'backend/securityMiddleware.ts': 'EMBEDDED_ANCHOR',
      'backend/audit/verifiableReportService.ts': 'EMBEDDED_ANCHOR'
    }
  },
  signature: '5j7e4q0K3slB+bw/n5hKuOAvTePqbojnwkjK0WkQs6dN6TMHaGrnnH87NCn51UhKmQFcw2T1joA/Blh3w7GdCg==',
  publicKeyId: 'fs-fim-root-2026'
};

