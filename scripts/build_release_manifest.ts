import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const PROTECTED_FILES = [
  'backend/auth.ts',
  'backend/db.ts',
  'backend/licensing.ts',
  'backend/routes.ts',
  'backend/securityMiddleware.ts',
  'backend/osKeyProtection.ts',
  'backend/fimManifest.ts',
  'backend/fimService.ts',
  'backend/licensing/offlineLicense.ts',
  'backend/licensing/protectedLicenseStore.ts',
  'backend/licensing/clockMonitor.ts',
  'backend/audit/verifiableReportService.ts',
  'backend/scanJobManager.ts',
  'backend/scannerEngine.ts',
  'backend/scanScheduler.ts',
  'backend/billing.ts',
  'backend/telemetry.ts',
  'backend/privacyGovernance.ts',
  'backend/pilotService.ts',
  'backend/evidenceEngine.ts'
];

function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function buildManifest() {
  const baseDir = process.cwd();
  const fileHashes: Record<string, string> = {};

  const privKeyPath = path.join(baseDir, 'fim_release_private.key');
  const pubKeyPath = path.join(baseDir, 'fim_release_public.key');
  if (!fs.existsSync(privKeyPath) || !fs.existsSync(pubKeyPath)) {
    throw new Error('Release keypair fim_release_private.key or fim_release_public.key not found.');
  }

  const privateKey = fs.readFileSync(privKeyPath, 'utf8');
  const publicKey = fs.readFileSync(pubKeyPath, 'utf8');

  // Sync public key in backend/fimManifest.ts
  const fimManifestPath = path.join(baseDir, 'backend/fimManifest.ts');
  let fimManifestContent = fs.readFileSync(fimManifestPath, 'utf8');
  fimManifestContent = fimManifestContent.replace(
    /export const TRUSTED_FIM_PUBLIC_KEY = `[\s\S]*?`;/,
    `export const TRUSTED_FIM_PUBLIC_KEY = \`${publicKey.trim()}\`;`
  );
  fs.writeFileSync(fimManifestPath, fimManifestContent, 'utf8');

  // Re-read file hashes after updating fimManifest.ts
  for (const relPath of PROTECTED_FILES) {
    const fullPath = path.join(baseDir, relPath);
    if (fs.existsSync(fullPath)) {
      fileHashes[relPath] = computeFileHash(fullPath);
    }
  }

  const payload = {
    version: '8.2.0-rc1',
    issuedAt: new Date().toISOString(),
    files: fileHashes
  };
  const canonicalizeJson = (obj: any): string => {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(canonicalizeJson).join(',') + ']';
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',') + '}';
  };
  const canonical = canonicalizeJson(payload);
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), Buffer.from(privateKey, 'utf8')).toString('base64');

  const signedManifest = {
    payload,
    signature,
    publicKeyId: 'fs-fim-root-2026'
  };

  fs.writeFileSync(path.join(baseDir, 'release_manifest.json'), JSON.stringify(signedManifest, null, 2), 'utf8');
  console.log('Successfully generated signed release_manifest.json with', Object.keys(fileHashes).length, 'files.');
  console.log(JSON.stringify(signedManifest, null, 2));
}

buildManifest();
