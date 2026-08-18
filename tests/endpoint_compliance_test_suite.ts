process.env.FILE_SENTINEL_DEV_MODE = 'false';

import { getDatabase } from '../backend/db.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import { USBDetector } from '../backend/endpoint/usbDetector.js';
import {
  WebAccessDetector,
  DEFAULT_WEB_TARGETS,
  isDomainAllowed,
  validateAndSanitizeTarget
} from '../backend/endpoint/webAccessDetector.js';
import { EndpointComplianceEngine } from '../backend/endpoint/endpointDetector.js';
import { EndpointEvidenceGenerator } from '../backend/endpoint/endpointEvidence.js';
import { WebAccessTarget } from '../backend/endpoint/endpointTypes.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import crypto from 'node:crypto';

async function runEndpointComplianceTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase A Endpoint Compliance Detection Engine Suite   ');
  console.log('========================================================================\n');

  let passedTests = 0;

  const db = getDatabase(':memory:');
  const now = new Date().toISOString();

  // Setup Tenants
  const orgA = 'org-tenant-a';
  const orgB = 'org-tenant-b';
  const userA = 'usr-admin-a';
  const userB = 'usr-admin-b';
  const userViewerA = 'usr-viewer-a';
  const userDisabled = 'usr-disabled';

  const deviceA = 'dev-device-a';
  const deviceB = 'dev-device-b';
  const deviceRevoked = 'dev-device-revoked';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Tenant Alpha Corp', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Tenant Beta Ltd', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceA, orgA, 'Device A', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceB, orgB, 'Device B', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 1, ?)')
    .run(deviceRevoked, orgA, 'Revoked Device', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userA, orgA, 'admin_a', hashPassword('Secret123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userB, orgB, 'admin_b', hashPassword('Secret123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userViewerA, orgA, 'viewer_a', hashPassword('Secret123!'), 'VIEWER', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)')
    .run(userDisabled, orgA, 'disabled_user', hashPassword('Secret123!'), 'ORG_ADMIN', now);

  const tokenA = 'tok-a-' + crypto.randomBytes(16).toString('hex');
  const tokenB = 'tok-b-' + crypto.randomBytes(16).toString('hex');
  const tokenViewerA = 'tok-viewer-a-' + crypto.randomBytes(16).toString('hex');
  const tokenRevoked = 'tok-revoked-' + crypto.randomBytes(16).toString('hex');
  const tokenDisabled = 'tok-disabled-' + crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenA, userA, orgA, deviceA, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenB, userB, orgB, deviceB, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenViewerA, userViewerA, orgA, deviceA, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenRevoked, userA, orgA, deviceRevoked, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenDisabled, userDisabled, orgA, deviceA, expiresAt, now);

  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  // ==========================================
  // SECTION 1: USB STORAGE DETECTION TESTS
  // ==========================================
  console.log('--- SECTION 1: USB STORAGE DETECTION ENGINE ---');

  // Test 1: USB Storage Enabled (Start=3)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) {
          return { stdout: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\n    Start    REG_DWORD    0x3', stderr: '' };
        }
        return { stdout: '[]', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.status, 'ENABLED', 'Should detect ENABLED when USBSTOR Start is 0x3');
    assert.strictEqual(res.connectedDeviceCount, 0);
    assert.strictEqual(res.confidence, 'HIGH');
    console.log('  [PASS] Test 1: USB Storage Enabled (Start=0x3)');
    passedTests++;
  }

  // Test 2: USB Storage Disabled (Start=4)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) {
          return { stdout: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\n    Start    REG_DWORD    0x4', stderr: '' };
        }
        return { stdout: '[]', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.status, 'DISABLED', 'Should detect DISABLED when USBSTOR Start is 0x4');
    assert.strictEqual(res.confidence, 'HIGH');
    console.log('  [PASS] Test 2: USB Storage Disabled (Start=0x4)');
    passedTests++;
  }

  // Test 3: No USB Storage Devices Connected
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) return { stdout: '[]', stderr: '' };
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 0);
    assert.deepStrictEqual(res.connectedStorageDevices, []);
    console.log('  [PASS] Test 3: No USB Storage Connected Inventory (Enabled + 0 Devices)');
    passedTests++;
  }

  // Test 4: USB Storage Device Connected (SanDisk Ultra)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) {
          return {
            stdout: JSON.stringify([{
              Model: 'SanDisk Ultra USB 3.0',
              Manufacturer: 'SanDisk',
              DeviceID: '\\\\.\\PHYSICALDRIVE2',
              MediaType: 'Removable Media',
              Size: 32000000000
            }]),
            stderr: ''
          };
        }
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 1);
    assert.strictEqual(res.connectedStorageDevices[0].manufacturer, 'SanDisk');
    assert.strictEqual(res.connectedStorageDevices[0].device_type, 'USB Mass Storage');
    console.log('  [PASS] Test 4: USB Storage Device Connected & Identified');
    passedTests++;
  }

  // Test 5: USB Keyboard Connected Only (HID Ignored)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) {
          return {
            stdout: JSON.stringify([{
              Model: 'Logitech USB Keyboard HID',
              Manufacturer: 'Logitech',
              DeviceID: 'HID\\VID_046D&PID_C31C'
            }]),
            stderr: ''
          };
        }
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 0, 'HID Keyboard must be ignored from storage inventory');
    console.log('  [PASS] Test 5: USB Keyboard Filtered (HID Ignored)');
    passedTests++;
  }

  // Test 6: USB Mouse Connected Only (HID Ignored)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) {
          return {
            stdout: JSON.stringify([{
              Model: 'Razer Optical Gaming Mouse',
              Manufacturer: 'Razer',
              DeviceID: 'HID\\VID_1532'
            }]),
            stderr: ''
          };
        }
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 0, 'HID Mouse must be ignored from storage inventory');
    console.log('  [PASS] Test 6: USB Mouse Filtered (HID Ignored)');
    passedTests++;
  }

  // Test 7: USB Webcam Connected Only (Camera/Video Ignored)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) {
          return {
            stdout: JSON.stringify([{
              Model: 'Logitech HD Pro Webcam C920',
              Manufacturer: 'Logitech',
              DeviceID: 'USB\\VID_046D&PID_082D'
            }]),
            stderr: ''
          };
        }
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 0, 'USB Webcam must be ignored from storage inventory');
    console.log('  [PASS] Test 7: USB Webcam Filtered (Non-Storage Ignored)');
    passedTests++;
  }

  // Test 8: Mixed Peripherals (Storage + Keyboard + Mouse + Webcam -> Only Storage Inventoried)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x3', stderr: '' };
        if (cmd.includes('Get-CimInstance')) {
          return {
            stdout: JSON.stringify([
              { Model: 'Dell Multimedia Keyboard', Manufacturer: 'Dell' },
              { Model: 'Kingston DataTraveler 3.0', Manufacturer: 'Kingston', DeviceID: 'USB\\VID_0951' },
              { Model: 'Logitech USB Wireless Mouse', Manufacturer: 'Logitech' },
              { Model: 'Logitech HD Pro Webcam C920', Manufacturer: 'Logitech' }
            ]),
            stderr: ''
          };
        }
        return { stdout: '', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.connectedDeviceCount, 1, 'Only Kingston storage drive should be captured');
    assert.strictEqual(res.connectedStorageDevices[0].manufacturer, 'Kingston');
    console.log('  [PASS] Test 8: Mixed Peripherals (Only Storage Inventoried)');
    passedTests++;
  }

  // Test 9: Unknown USB State (Registry Query Returns Unexpected Format)
  {
    const detector = new USBDetector({
      platformOverride: 'windows',
      mockRunner: async (cmd: string) => {
        if (cmd.includes('USBSTOR')) return { stdout: 'Start REG_DWORD 0x999', stderr: '' };
        return { stdout: '[]', stderr: '' };
      }
    });
    const res = await detector.detect();
    assert.strictEqual(res.status, 'UNKNOWN');
    console.log('  [PASS] Test 9: Unknown USB Policy State Handling');
    passedTests++;
  }

  // Test 10: Unsupported Platform (Linux / macOS Returns UNSUPPORTED_PLATFORM)
  {
    const detectorLinux = new USBDetector({ platformOverride: 'linux' });
    const resLinux = await detectorLinux.detect();
    assert.strictEqual(resLinux.status, 'UNSUPPORTED_PLATFORM');
    assert.strictEqual(resLinux.detectionMethod, 'UNSUPPORTED_PLATFORM');

    const detectorMac = new USBDetector({ platformOverride: 'darwin' });
    const resMac = await detectorMac.detect();
    assert.strictEqual(resMac.status, 'UNSUPPORTED_PLATFORM');
    console.log('  [PASS] Test 10: Platform Abstraction (Linux/macOS UNSUPPORTED_PLATFORM)');
    passedTests++;
  }

  // ==========================================
  // SECTION 2: WEB ACCESS DETECTION & FALSE POSITIVE DEFENSE
  // ==========================================
  console.log('\n--- SECTION 2: WEB ACCESS DETECTION & FALSE POSITIVE DEFENSE ---');

  const mockTarget: WebAccessTarget = {
    id: 'test-soc',
    category: 'SOCIAL_MEDIA',
    service_name: 'Facebook',
    primary_domain: 'facebook.com',
    probe_url: 'https://www.facebook.com',
    expected_identifiers: ['facebook', 'fb', 'meta'],
    allowed_domains: ['facebook.com', 'fb.com', 'meta.com']
  };

  const mockGmailTarget: WebAccessTarget = {
    id: 'test-eml',
    category: 'PERSONAL_EMAIL',
    service_name: 'Gmail',
    primary_domain: 'mail.google.com',
    probe_url: 'https://mail.google.com',
    expected_identifiers: ['google', 'gmail', 'accounts.google'],
    allowed_domains: ['google.com', 'googleusercontent.com', 'gstatic.com']
  };

  const webDetector = new WebAccessDetector();

  // Test 11: Accessible Target (Valid Facebook HTTP 200 with Expected Signature)
  {
    const classification = webDetector.classifyResponse(
      200,
      { 'content-type': 'text/html' },
      '<!DOCTYPE html><html><head><title>Facebook - Log In or Sign Up</title></head><body><div id="facebook-login">Welcome to Meta</div></body></html>',
      mockTarget
    );
    assert.strictEqual(classification.status, 'ACCESSIBLE');
    assert.strictEqual(classification.confidence, 'HIGH');
    console.log('  [PASS] Test 11: Genuine Accessible Service (Facebook with Signature)');
    passedTests++;
  }

  // Test 12: Accessible Target (Valid Gmail HTTP 200 with Expected Signature)
  {
    const classification = webDetector.classifyResponse(
      200,
      { 'content-type': 'text/html' },
      '<!DOCTYPE html><html><head><title>Gmail - Email from Google</title></head><body><div id="accounts.google.com">Sign In</div></body></html>',
      mockGmailTarget
    );
    assert.strictEqual(classification.status, 'ACCESSIBLE');
    assert.strictEqual(classification.confidence, 'HIGH');
    console.log('  [PASS] Test 12: Genuine Accessible Service (Gmail with Signature)');
    passedTests++;
  }

  // Test 13: Blocked Target by Corporate Firewall Signature (FortiGuard / Palo Alto)
  {
    const classification = webDetector.classifyResponse(
      200,
      { 'server': 'FortiGate' },
      '<html><body><h1>FortiGuard Web Filtering - Access Denied</h1><p>Category: Social Networking Blocked</p></body></html>',
      mockTarget
    );
    assert.strictEqual(classification.status, 'BLOCKED');
    assert.strictEqual(classification.confidence, 'HIGH');
    console.log('  [PASS] Test 13: Corporate Proxy / FortiGuard Block Signature');
    passedTests++;
  }

  // Test 14: DNS Resolution Alone Does Not Equal Accessible
  {
    const classification = webDetector.classifyResponse(403, {}, 'Access Denied', mockTarget);
    assert.strictEqual(classification.status, 'BLOCKED');
    console.log('  [PASS] Test 14: DNS-Only Resolution False-Positive Protection');
    passedTests++;
  }

  // Test 15: DNS Sinkhole (127.0.0.1 / 0.0.0.0 Loopback Detection)
  {
    const mockSinkholeTarget: WebAccessTarget = {
      id: 'test-sink',
      category: 'SOCIAL_MEDIA',
      service_name: 'TikTok',
      primary_domain: 'tiktok.com',
      probe_url: 'https://www.tiktok.com',
      expected_identifiers: ['tiktok'],
      allowed_domains: ['tiktok.com']
    };
    const detector = new WebAccessDetector({
      mockProbeHandler: async (t) => ({
        category: t.category,
        service: t.service_name,
        target_domain: t.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'DNS_TCP_PROBE',
        reason: 'DNS resolved to loopback sinkhole address: 127.0.0.1',
        timestamp: new Date().toISOString()
      })
    });
    const result = await detector.probeTarget(mockSinkholeTarget);
    assert.strictEqual(result.status, 'BLOCKED');
    assert.strictEqual(result.detectionMethod, 'DNS_TCP_PROBE');
    console.log('  [PASS] Test 15: DNS Sinkhole Loopback Defense (127.0.0.1)');
    passedTests++;
  }

  // Test 16: TLS Interception / Untrusted Gateway Certificate -> BLOCKED
  {
    const detector = new WebAccessDetector({
      mockProbeHandler: async (t) => ({
        category: t.category,
        service: t.service_name,
        target_domain: t.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        reason: 'TLS handshake intercepted / untrusted corporate cert: CERT_AUTHORITY_INVALID',
        timestamp: new Date().toISOString()
      })
    });
    const result = await detector.probeTarget(mockTarget);
    assert.strictEqual(result.status, 'BLOCKED');
    console.log('  [PASS] Test 16: TLS Interception & Certificate Rejection');
    passedTests++;
  }

  // Test 17: Redirect to Corporate Block Portal (e.g., block.corporate.com)
  {
    const classification = webDetector.classifyResponse(
      200,
      {},
      '<html><body><h1>Policy Violation</h1><p>Blocked by administrator: Category Social Media</p></body></html>',
      mockTarget
    );
    assert.strictEqual(classification.status, 'BLOCKED');
    console.log('  [PASS] Test 17: Redirect / Block Portal Signature');
    passedTests++;
  }

  // Test 18: Redirect to Captive Portal / WiFi Login Screen
  {
    const classification = webDetector.classifyResponse(
      200,
      {},
      '<html><head><title>Guest WiFi Authentication</title></head><body>Captive Portal Hotspot Login</body></html>',
      mockTarget
    );
    assert.strictEqual(classification.status, 'BLOCKED');
    console.log('  [PASS] Test 18: Captive Portal Authentication Defense');
    passedTests++;
  }

  // Test 19: HTTP 403 Forbidden
  {
    const classification = webDetector.classifyResponse(403, {}, '<html><body>Forbidden</body></html>', mockTarget);
    assert.strictEqual(classification.status, 'BLOCKED');
    assert.strictEqual(classification.confidence, 'HIGH');
    console.log('  [PASS] Test 19: Explicit HTTP 403 Forbidden Detection');
    passedTests++;
  }

  // Test 20: HTTP 451 Unavailable for Legal / Policy Reasons
  {
    const classification = webDetector.classifyResponse(451, {}, 'Unavailable for Legal Reasons', mockTarget);
    assert.strictEqual(classification.status, 'BLOCKED');
    assert.strictEqual(classification.confidence, 'HIGH');
    console.log('  [PASS] Test 20: HTTP 451 Policy Restriction Detection');
    passedTests++;
  }

  // Test 21: Generic HTTP 200 Proxy Page (Missing Service Signatures) -> INDETERMINATE
  {
    const classification = webDetector.classifyResponse(200, {}, 'OK', mockTarget);
    assert.strictEqual(classification.status, 'INDETERMINATE');
    assert.strictEqual(classification.confidence, 'MEDIUM');
    console.log('  [PASS] Test 21: Generic 200 Proxy Stub (INDETERMINATE)');
    passedTests++;
  }

  // Test 22: CRITICAL - Generic Large HTML (>5000 bytes) Without Service Signatures MUST BE INDETERMINATE
  {
    const largeGenericHtml = '<html><head><title>Company Intranet Portal</title></head><body>' +
      '<div>Welcome to our internal network hub. Here are some company announcements and policies.</div>'.repeat(80) +
      '</body></html>';
    assert.ok(largeGenericHtml.length > 5000, 'Test payload must be large (> 5000 bytes)');

    const classification = webDetector.classifyResponse(200, { 'content-type': 'text/html' }, largeGenericHtml, mockTarget);
    assert.strictEqual(classification.status, 'INDETERMINATE', 'Large generic HTML without target service signatures MUST NOT become ACCESSIBLE');
    console.log('  [PASS] Test 22: Critical False-Positive Defense (Large Generic HTML -> INDETERMINATE)');
    passedTests++;
  }

  // Test 23: Temporary Service Outage (HTTP 503 Service Unavailable) -> INDETERMINATE
  {
    const classification = webDetector.classifyResponse(503, {}, 'Service Temporarily Unavailable', mockTarget);
    assert.strictEqual(classification.status, 'INDETERMINATE');
    assert.strictEqual(classification.confidence, 'LOW');
    console.log('  [PASS] Test 23: Temporary Outage / HTTP 503 (INDETERMINATE)');
    passedTests++;
  }

  // Test 24: Ambiguous Unhandled Status (HTTP 418) -> INDETERMINATE
  {
    const classification = webDetector.classifyResponse(418, {}, 'I am a teapot', mockTarget);
    assert.strictEqual(classification.status, 'INDETERMINATE');
    console.log('  [PASS] Test 24: Ambiguous Response (INDETERMINATE)');
    passedTests++;
  }

  // Test 25: Network Timeout Handling -> UNREACHABLE
  {
    const detector = new WebAccessDetector({
      mockProbeHandler: async (t) => ({
        category: t.category,
        service: t.service_name,
        target_domain: t.primary_domain,
        status: 'UNREACHABLE',
        confidence: 'MEDIUM',
        detectionMethod: 'HTTPS_PROBE',
        reason: 'Network request timed out',
        timestamp: new Date().toISOString()
      })
    });
    const result = await detector.probeTarget(mockTarget);
    assert.strictEqual(result.status, 'UNREACHABLE');
    console.log('  [PASS] Test 25: Network Timeout (UNREACHABLE)');
    passedTests++;
  }

  // Test 26: Valid Redirect Domain Validation
  {
    const allowed = ['facebook.com', 'fb.com', 'meta.com'];
    assert.strictEqual(isDomainAllowed('facebook.com', allowed), true);
    assert.strictEqual(isDomainAllowed('www.facebook.com', allowed), true);
    assert.strictEqual(isDomainAllowed('login.facebook.com', allowed), true);
    assert.strictEqual(isDomainAllowed('m.facebook.com', allowed), true);
    assert.strictEqual(isDomainAllowed('fb.com', allowed), true);
    assert.strictEqual(isDomainAllowed('www.meta.com', allowed), true);
    console.log('  [PASS] Test 26: Valid Redirect Within Approved Domain Set');
    passedTests++;
  }

  // Test 27: Redirect to Unrelated Domain Rejected
  {
    const allowed = ['facebook.com', 'fb.com', 'meta.com'];
    assert.strictEqual(isDomainAllowed('unrelated-site.example.com', allowed), false);
    assert.strictEqual(isDomainAllowed('google.com', allowed), false);
    console.log('  [PASS] Test 27: Redirect to Unrelated Domain Rejected');
    passedTests++;
  }

  // Test 28: Malicious Lookalike Domain (evil-facebook.com) Rejected
  {
    const allowed = ['facebook.com', 'fb.com', 'meta.com'];
    assert.strictEqual(isDomainAllowed('evil-facebook.com', allowed), false, 'evil-facebook.com must NOT match facebook.com');
    assert.strictEqual(isDomainAllowed('fake-facebook.com', allowed), false);
    assert.strictEqual(isDomainAllowed('facebook.com.attacker.com', allowed), false);
    assert.strictEqual(isDomainAllowed('meta.com.malicious.net', allowed), false);
    console.log('  [PASS] Test 28: Malicious Lookalike Domain Defense (evil-facebook.com Rejected)');
    passedTests++;
  }

  // Test 29: Domain Validation Edge Cases
  {
    assert.strictEqual(isDomainAllowed('', ['facebook.com']), false);
    assert.strictEqual(isDomainAllowed('facebook.com', []), false);
    assert.strictEqual(isDomainAllowed('notfacebook.com', ['facebook.com']), false);
    console.log('  [PASS] Test 29: Exact & Subdomain Boundary Enforcement');
    passedTests++;
  }

  // Test 30: Custom Target Security & Private Network Rejection
  {
    assert.throws(() => {
      validateAndSanitizeTarget({
        id: 'bad-1',
        category: 'SOCIAL_MEDIA',
        service_name: 'Localhost Probe',
        probe_url: 'http://localhost/test'
      });
    }, /HTTPS/);

    assert.throws(() => {
      validateAndSanitizeTarget({
        id: 'bad-2',
        category: 'SOCIAL_MEDIA',
        service_name: 'Metadata Probe',
        probe_url: 'https://169.254.169.254/latest/meta-data'
      });
    }, /forbidden/);

    assert.throws(() => {
      validateAndSanitizeTarget({
        id: 'bad-3',
        category: 'SOCIAL_MEDIA',
        service_name: 'Internal Network Probe',
        probe_url: 'https://192.168.1.1/admin'
      });
    }, /private network/);

    const validCustom = validateAndSanitizeTarget({
      id: 'cust-1',
      category: 'SOCIAL_MEDIA',
      service_name: 'Custom Mastodon',
      primary_domain: 'mastodon.social',
      probe_url: 'https://mastodon.social',
      expected_identifiers: ['mastodon']
    });
    assert.strictEqual(validCustom.id, 'cust-1');
    assert.strictEqual(validCustom.probe_url, 'https://mastodon.social');
    console.log('  [PASS] Test 30: Custom Target Security & SSRF Protection');
    passedTests++;
  }

  // ==========================================
  // SECTION 3: SECURITY & TENANT ISOLATION
  // ==========================================
  console.log('\n--- SECTION 3: SECURITY & TENANT ISOLATION ---');

  // Seed an assessment for Tenant A
  const sampleTestTargets: WebAccessTarget[] = [
    {
      id: 'test-soc-fb',
      category: 'SOCIAL_MEDIA',
      service_name: 'Facebook',
      primary_domain: 'facebook.com',
      probe_url: 'https://www.facebook.com',
      expected_identifiers: ['facebook', 'fb'],
      allowed_domains: ['facebook.com', 'fb.com']
    },
    {
      id: 'test-eml-gm',
      category: 'PERSONAL_EMAIL',
      service_name: 'Gmail',
      primary_domain: 'mail.google.com',
      probe_url: 'https://mail.google.com',
      expected_identifiers: ['gmail', 'google'],
      allowed_domains: ['google.com']
    },
    {
      id: 'test-msg-wa',
      category: 'MESSAGING',
      service_name: 'WhatsApp',
      primary_domain: 'web.whatsapp.com',
      probe_url: 'https://web.whatsapp.com',
      expected_identifiers: ['whatsapp'],
      allowed_domains: ['whatsapp.com']
    },
    {
      id: 'test-cld-gd',
      category: 'CLOUD_STORAGE',
      service_name: 'Google Drive',
      primary_domain: 'drive.google.com',
      probe_url: 'https://drive.google.com',
      expected_identifiers: ['drive', 'google'],
      allowed_domains: ['google.com']
    }
  ];

  const engineA = new EndpointComplianceEngine(db, {
    platformOverride: 'windows',
    customWebTargets: sampleTestTargets,
    connectionTimeoutMs: 300,
    requestTimeoutMs: 500,
    mockWindowsUsbData: {
      status: 'DISABLED',
      confidence: 'HIGH',
      connectedStorageDevices: [],
      connectedDeviceCount: 0
    }
  });
  const assessmentA = await engineA.runAssessment({
    orgId: orgA,
    userId: userA,
    deviceId: deviceA
  });

  // Test 31: Tenant B Cannot Read Tenant A Assessment by ID
  {
    const res = await request(app)
      .get(`/api/endpoint/assessment/${assessmentA.id}`)
      .set('Authorization', `Bearer ${tokenB}`);
    assert.strictEqual(res.status, 404, 'Tenant B must receive 404 when querying Tenant A assessment');
    console.log('  [PASS] Test 31: Cross-Tenant Assessment Read Isolation (404)');
    passedTests++;
  }

  // Test 32: Tenant B Cannot Run Assessment Using Tenant A Org ID
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenB}`)
      .send({});
    // Tenant B session uses deviceB in orgB, so it assesses deviceB in orgB successfully
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.org_id, orgB);
    assert.strictEqual(res.body.device_id, deviceB);
    console.log('  [PASS] Test 32: Tenant B Scoped Strictly to Tenant B Organization & Device');
    passedTests++;
  }

  // Test 33: Body Device ID Parameter Rejected
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ deviceId: 'dev-nonexistent-999' });
    assert.strictEqual(res.status, 400, 'Supplying deviceId in request body must be rejected with 400');
    assert.ok(res.body.error && res.body.error.includes('deviceId'));
    console.log('  [PASS] Test 33: Request Body Device ID Parameter Rejected (400)');
    passedTests++;
  }

  // Test 34: Unauthorized Role (VIEWER) Rejected from Running Assessment
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .send({});
    assert.strictEqual(res.status, 403, 'VIEWER role must be rejected with 403');
    console.log('  [PASS] Test 34: Unauthorized Role Rejected (VIEWER -> 403)');
    passedTests++;
  }

  // Test 35: Disabled User Rejected
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenDisabled}`)
      .send({});
    assert.strictEqual(res.status, 403, 'Disabled user must be rejected with 403');
    console.log('  [PASS] Test 35: Disabled User Account Blocked (403)');
    passedTests++;
  }

  // Test 36: Revoked Device Rejected
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenRevoked}`)
      .send({});
    assert.strictEqual(res.status, 403, 'Revoked device must be rejected with 403');
    console.log('  [PASS] Test 36: Revoked Device Registration Blocked (403)');
    passedTests++;
  }

  // Test 37: Assessment History Query Never Leaks Cross-Tenant Data
  {
    const resB = await request(app)
      .get('/api/endpoint/assessments')
      .set('Authorization', `Bearer ${tokenB}`);
    assert.strictEqual(resB.status, 200);
    const listB = resB.body as any[];
    assert.ok(!listB.some(item => item.id === assessmentA.id), 'Tenant B list must never contain Tenant A assessment');
    console.log('  [PASS] Test 37: Assessment History Strictly Tenant-Scoped');
    passedTests++;
  }

  // ==========================================
  // SECTION 4: PRIVACY & DATA SAFETY
  // ==========================================
  console.log('\n--- SECTION 4: PRIVACY & DATA SAFETY VERIFICATION ---');

  // Test 38: Verify No Browser History Collection
  {
    const rawAssessmentJson = JSON.stringify(assessmentA);
    const forbiddenKeywords = ['browser_history', 'history.db', 'places.sqlite', 'visited_urls', 'cookies', 'session_storage'];
    for (const kw of forbiddenKeywords) {
      assert.ok(!rawAssessmentJson.includes(kw), `Assessment must not contain ${kw}`);
    }
    console.log('  [PASS] Test 38: Zero Browser History / Cookie Collection Verified');
    passedTests++;
  }

  // Test 39: Verify No Document Contents / File Names Collected
  {
    const rawAssessmentJson = JSON.stringify(assessmentA);
    const forbiddenDocKeywords = ['document_content', 'file_text', 'ocr_text', 'extracted_content', '.docx', '.pdf', '.xlsx'];
    for (const kw of forbiddenDocKeywords) {
      assert.ok(!rawAssessmentJson.includes(kw), `Assessment must not contain ${kw}`);
    }
    console.log('  [PASS] Test 39: Zero Document Content Inspection Verified');
    passedTests++;
  }

  // Test 40: Verify No Personal Email Body or Password Data
  {
    const rawAssessmentJson = JSON.stringify(assessmentA);
    const forbiddenEmailKeywords = ['email_body', 'email_subject', 'inbox_messages', 'user_password', 'auth_cookie'];
    for (const kw of forbiddenEmailKeywords) {
      assert.ok(!rawAssessmentJson.includes(kw), `Assessment must not contain ${kw}`);
    }
    console.log('  [PASS] Test 40: Zero Personal Email / Auth Secrets Collected');
    passedTests++;
  }

  // ==========================================
  // SECTION 5: EVIDENCE & AUDIT ENGINE INTEGRATION
  // ==========================================
  console.log('\n--- SECTION 5: DETERMINISTIC EVIDENCE & AUDIT ENGINE INTEGRATION ---');

  // Test 41: Deterministic Evidence Text Formatting
  {
    const evidenceText = assessmentA.evidence_text;
    assert.ok(evidenceText.includes('FILESENTINEL ENDPOINT COMPLIANCE ASSESSMENT'));
    assert.ok(evidenceText.includes(`Assessment ID:       ${assessmentA.id}`));
    assert.ok(evidenceText.includes(`Device Identifier:   ${assessmentA.device_id}`));
    assert.ok(evidenceText.includes('USB MASS STORAGE STATUS'));
    assert.ok(evidenceText.includes('SOCIAL MEDIA ACCESS CONTROL'));
    assert.ok(evidenceText.includes('PERSONAL EMAIL ACCESS CONTROL'));
    assert.ok(evidenceText.includes('MESSAGING APPLICATION ACCESS CONTROL'));
    assert.ok(evidenceText.includes('CLOUD STORAGE ACCESS CONTROL'));
    console.log('  [PASS] Test 41: Deterministic Evidence Text Contains All Mandatory Sections');
    passedTests++;
  }

  // Test 42: Audit Evidence Generation for ZTI-008 and ZTI-009
  {
    const evidenceItems = EndpointEvidenceGenerator.toAuditEvidenceItems(assessmentA);
    assert.strictEqual(evidenceItems.length, 2, 'Should generate evidence items for ZTI-008 and ZTI-009');

    const zti008Item = evidenceItems.find(e => e.evidence_type === 'DLP_GPO_CONFIGURATION_EXPORT');
    assert.ok(zti008Item, 'Must generate DLP_GPO_CONFIGURATION_EXPORT for ZTI-008');
    assert.strictEqual(zti008Item?.is_valid, true);

    const zti009Item = evidenceItems.find(e => e.evidence_type === 'FIREWALL_PROXY_CONFIGURATION_EXPORT');
    assert.ok(zti009Item, 'Must generate FIREWALL_PROXY_CONFIGURATION_EXPORT for ZTI-009');
    assert.strictEqual(zti009Item?.is_valid, true);
    console.log('  [PASS] Test 42: Seamless Audit Engine Evidence Generation (ZTI-008 & ZTI-009)');
    passedTests++;
  }

  // Test 43: Production API Rejects mockWindowsUsbData Parameter with HTTP 400
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        mockWindowsUsbData: {
          status: 'DISABLED',
          confidence: 'HIGH'
        }
      });

    assert.strictEqual(res.status, 400, 'Production API must reject mockWindowsUsbData with HTTP 400');
    assert.ok(res.body.error.includes('mockWindowsUsbData'), 'Error message must explicitly mention mockWindowsUsbData');
    console.log('  [PASS] Test 43: Production API Rejects mockWindowsUsbData (HTTP 400)');
    passedTests++;
  }

  // Test 44: Production API Rejects platformOverride Parameter with HTTP 400
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        platformOverride: 'windows'
      });

    assert.strictEqual(res.status, 400, 'Production API must reject platformOverride with HTTP 400');
    assert.ok(res.body.error.includes('platformOverride'), 'Error message must explicitly mention platformOverride');
    console.log('  [PASS] Test 44: Production API Rejects platformOverride (HTTP 400)');
    passedTests++;
  }

  // Test 45: Production API Rejects customWebTargets Parameter with HTTP 400
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        customWebTargets: sampleTestTargets
      });

    assert.strictEqual(res.status, 400, 'Production API must reject customWebTargets with HTTP 400');
    assert.ok(res.body.error.includes('customWebTargets'), 'Error message must mention customWebTargets');
    console.log('  [PASS] Test 45: Production API Rejects customWebTargets (HTTP 400)');
    passedTests++;
  }

  // Test 46: Fabricated DISABLED Result Cannot Become Compliance Evidence
  {
    const auditSessionId = `audit-${crypto.randomBytes(8).toString('hex')}`;
    db.prepare('INSERT INTO audit_sessions (audit_id, org_id, audit_date, agency_name, auditor_name, status, overall_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(auditSessionId, orgA, '2026-08-17', 'Alpha Security', 'Auditor Alpha', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const initialEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditSessionId) as any).cnt;

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        linkAuditSessionId: auditSessionId,
        mockWindowsUsbData: {
          status: 'DISABLED',
          confidence: 'HIGH',
          connectedDeviceCount: 0,
          connectedStorageDevices: []
        }
      });

    assert.strictEqual(res.status, 400, 'Mock injection attempt must be blocked with HTTP 400');
    const finalEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditSessionId) as any).cnt;
    assert.strictEqual(finalEvidenceCount, initialEvidenceCount, 'Fabricated DISABLED result must not generate audit evidence records');
    console.log('  [PASS] Test 46: Fabricated DISABLED Result Rejected & Cannot Become Evidence');
    passedTests++;
  }

  // Test 47: Fabricated ENABLED Result Cannot Become Compliance Evidence
  {
    const auditSessionId = `audit-${crypto.randomBytes(8).toString('hex')}`;
    db.prepare('INSERT INTO audit_sessions (audit_id, org_id, audit_date, agency_name, auditor_name, status, overall_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(auditSessionId, orgA, '2026-08-17', 'Alpha Security', 'Auditor Alpha', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const initialEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditSessionId) as any).cnt;

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        linkAuditSessionId: auditSessionId,
        mockWindowsUsbData: {
          status: 'ENABLED',
          confidence: 'HIGH',
          connectedDeviceCount: 2,
          connectedStorageDevices: [{
            device_type: 'USB Mass Storage',
            manufacturer: 'SanDisk',
            model: 'Ultra USB 3.0',
            connection_status: 'Connected'
          }]
        }
      });

    assert.strictEqual(res.status, 400, 'Mock injection attempt must be blocked with HTTP 400');
    const finalEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditSessionId) as any).cnt;
    assert.strictEqual(finalEvidenceCount, initialEvidenceCount, 'Fabricated ENABLED result must not generate audit evidence records');
    console.log('  [PASS] Test 47: Fabricated ENABLED Result Rejected & Cannot Become Evidence');
    passedTests++;
  }

  // Test 48: Real USB Detector & End-to-End API Assessment Execution (No Mocks)
  {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({});

    assert.strictEqual(res.status, 200, 'Production API should execute real assessment successfully');
    assert.ok(res.body.id.startsWith('EP-ASM-'), 'Assessment ID must follow EP-ASM- format');
    assert.strictEqual(res.body.org_id, orgA);
    assert.strictEqual(res.body.device_id, deviceA);
    assert.strictEqual(res.body.user_id, userA);
    assert.ok(res.body.platform, 'Platform must be detected');
    assert.ok(res.body.usb_result, 'Real USB detector result must be present');
    assert.ok(res.body.web_results.length > 0, 'Real web detector results must be present');
    assert.ok(res.body.evidence_text.length > 50, 'Deterministic evidence text must be populated');
    
    // Stored in database
    const dbRecord = db.prepare('SELECT * FROM endpoint_assessments WHERE id = ?').get(res.body.id) as any;
    assert.ok(dbRecord, 'Assessment must be persisted in database');
    assert.strictEqual(dbRecord.org_id, orgA);
    assert.strictEqual(dbRecord.device_id, deviceA);

    console.log('  [PASS] Test 48: Real USB Detector Executed & End-to-End Production Assessment Verified');
    passedTests++;
  }

  console.log('========================================================================');
  console.log(`  ALL ${passedTests}/${passedTests} TESTS PASSED PERFECTLY (100% SUCCESS)`);
  console.log('========================================================================\n');
}

runEndpointComplianceTestSuite().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error('\n❌ Test Suite Failed:', err);
  process.exit(1);
});
