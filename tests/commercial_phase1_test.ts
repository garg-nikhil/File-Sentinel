import { getDatabase } from '../backend/db.js';
import { hashPassword, verifyPassword } from '../backend/auth.js';
import crypto from 'node:crypto';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { createApiRouter } from '../backend/routes.js';

async function runPhase1Tests() {
  console.log('================================================================');
  console.log('   FileSentinel Commercialization Phase 1: Identity & Tenant Test ');
  console.log('================================================================');

  const db = getDatabase(':memory:');

  // Test 1: Password hashing and verification
  const rawPwd = 'SecurePassword123!';
  const hashed = hashPassword(rawPwd);
  assert.ok(hashed.includes(':'), 'Hashed password contains salt separator');
  assert.strictEqual(verifyPassword(rawPwd, hashed), true, 'Valid password verifies successfully');
  assert.strictEqual(verifyPassword('WrongPassword', hashed), false, 'Invalid password rejected');
  console.log('  ✔ [TEST 1] Password hashing and verification passed.');

  // Setup express test app with API router
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  // Test 2: Default seed user login
  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'devadmin', password: 'devpassword' });

  assert.strictEqual(loginRes.status, 200, 'Default admin login succeeds');
  assert.ok(loginRes.body.token, 'Session token returned');
  const token = loginRes.body.token;
  const orgId = loginRes.body.user.org_id;
  const adminUserId = loginRes.body.user.user_id;
  console.log('  ✔ [TEST 2] Default seed login and session token verified.');

  // Test 3: Invalid credentials login failure & security event audit
  const badLoginRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'devadmin', password: 'wrongpassword' });
  assert.strictEqual(badLoginRes.status, 401, 'Invalid credentials return 401');

  const secEvents = db.prepare("SELECT * FROM security_audit_events WHERE event_type = 'LOGIN_FAILURE'").all();
  assert.ok(secEvents.length > 0, 'Security audit event recorded for login failure');
  console.log('  ✔ [TEST 3] Invalid credentials rejected and logged to security_audit_events.');

  // Test 4: Create Organization B and User in Org B (Tenant isolation)
  const createOrgRes = await request(app)
    .post('/api/organizations/create')
    .set('Authorization', `Bearer ${token}`)
    .send({ name: 'Organization B' });
  assert.strictEqual(createOrgRes.status, 200);
  const orgBId = createOrgRes.body.org_id;

  const createUserRes = await request(app)
    .post('/api/users/create')
    .set('Authorization', `Bearer ${token}`)
    .send({ username: 'operatorB', password: 'password123', role: 'OPERATOR' });
  assert.strictEqual(createUserRes.status, 200);
  const userBId = createUserRes.body.user_id;
  // Note: userB is created under admin's org (orgId). Let's create an Org B user directly via SQL or api
  db.prepare('UPDATE users SET org_id = ? WHERE user_id = ?').run(orgBId, userBId);
  console.log('  ✔ [TEST 4] Organization and cross-tenant user setup completed.');

  // Test 5: Login as userB and verify cross-tenant scan restriction
  const loginBRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'operatorB', password: 'password123' });
  assert.strictEqual(loginBRes.status, 200);
  const tokenB = loginBRes.body.token;

  // Insert a scan belonging to Org A
  const scanAId = 'SCAN-ORG-A';
  db.prepare(`
    INSERT OR REPLACE INTO scans (scan_id, root_path, start_time, status, org_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(scanAId, '/tmp/a', new Date().toISOString(), 'COMPLETED', orgId);

  // User B tries to access Scan A -> should receive 404 or 403 (unauthorized / not found in tenant)
  const crossTenantRes = await request(app)
    .get(`/api/scans/${scanAId}`)
    .set('Authorization', `Bearer ${tokenB}`);
  assert.ok(crossTenantRes.status === 404 || crossTenantRes.status === 403, 'Cross-tenant scan access returns 404 or 403');
  console.log('  ✔ [TEST 5] Cross-tenant data isolation verified (User B cannot access Org A scan).');

  // Test 6: Device registration and revocation
  const regDeviceRes = await request(app)
    .post('/api/devices/register')
    .set('Authorization', `Bearer ${token}`)
    .send({ device_name: 'Workstation 01' });
  assert.strictEqual(regDeviceRes.status, 200);
  const deviceId = regDeviceRes.body.device_id;
  assert.ok(deviceId.startsWith('dev-'), 'Cryptographically random device_id generated');

  // Revoke device
  const revokeRes = await request(app)
    .post(`/api/devices/${deviceId}/revoke`)
    .set('Authorization', `Bearer ${token}`);
  assert.strictEqual(revokeRes.status, 200);

  const deviceRow = db.prepare('SELECT revoked FROM devices WHERE device_id = ?').get(deviceId) as any;
  assert.strictEqual(deviceRow.revoked, 1, 'Device marked as revoked in database');
  console.log('  ✔ [TEST 6] Device registration and revocation verified successfully.');

  // Test 7: Role restriction (Viewer trying to create user)
  // Create viewer user
  const viewerUserId = 'usr-viewer';
  db.prepare(`
    INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?)
  `).run(viewerUserId, orgId, 'viewer1', hashPassword('pwd'), 'VIEWER', new Date().toISOString());

  const loginViewerRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'viewer1', password: 'pwd' });
  const tokenViewer = loginViewerRes.body.token;

  const viewerActionRes = await request(app)
    .post('/api/users/create')
    .set('Authorization', `Bearer ${tokenViewer}`)
    .send({ username: 'hacker', password: 'pwd', role: 'ORG_ADMIN' });
  assert.strictEqual(viewerActionRes.status, 403, 'Viewer role restricted from creating users');
  console.log('  ✔ [TEST 7] Role authorization restrictions enforced successfully.');

  console.log('================================================================');
  console.log('   ALL PHASE 1 COMMERCIAL IDENTITY & TENANT TESTS PASSED (7/7)  ');
  console.log('================================================================');
  process.exit(0);
}

runPhase1Tests().catch(err => {
  console.error('Phase 1 test suite failed:', err);
  process.exit(1);
});
