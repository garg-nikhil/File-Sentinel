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

// Official FileSentinel Manufacturer Ed25519 Public Key (Public Key ONLY in app runtime)
export const TRUSTED_FIM_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAq88vM6tQlahXCOxoogfVSzPdyMfNeI8sEEp8D1Rt0zQ=
-----END PUBLIC KEY-----`;

/**
 * Validates that a manifest payload structure and hashes are strictly valid SHA-256 strings with no placeholders.
 */
export function isValidManifestStructure(manifest: SignedFimManifest): boolean {
  if (!manifest || !manifest.payload || !manifest.signature) return false;
  if (manifest.publicKeyId && manifest.publicKeyId !== 'fs-fim-root-2026') return false;

  const { payload } = manifest;
  if (!payload.version || !payload.issuedAt || !payload.files || typeof payload.files !== 'object') {
    return false;
  }

  const sha256Regex = /^[0-9a-f]{64}$/i;
  for (const [relPath, hash] of Object.entries(payload.files)) {
    if (!relPath || typeof relPath !== 'string') return false;
    if (typeof hash !== 'string' || !sha256Regex.test(hash)) {
      // Rejects any placeholder strings such as 'EMBEDDED_ANCHOR' or malformed hashes
      return false;
    }
  }

  return true;
}

export function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const keyVals = keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return '{' + keyVals.join(',') + '}';
}

/**
 * Cryptographically verifies a signed FIM manifest against the official Ed25519 public key.
 */
export function verifySignedFimManifest(manifest: SignedFimManifest, publicKeyPem: string = TRUSTED_FIM_PUBLIC_KEY): boolean {
  if (!isValidManifestStructure(manifest)) return false;
  try {
    const canonical = canonicalizeJson(manifest.payload);
    const dataBuf = Buffer.from(canonical, 'utf8');
    const sigBuf = Buffer.from(manifest.signature, 'base64');
    return crypto.verify(null, dataBuf, publicKeyPem, sigBuf);
  } catch {
    return false;
  }
}
