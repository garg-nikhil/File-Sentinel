import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { getDatabase } from '../backend/db.js';
import { createApiRouter } from '../backend/routes.js';
import { hashPassword } from '../backend/auth.js';
import crypto from 'node:crypto';

describe('COMMERCIALIZATION PHASE 10: FileSentinel Internal Admin Console Test Suite', () => {
  let app: express.Express;
  let db: any;
  let sysAdminToken: string;
  let orgAdminToken: string;
  let testOrgId: string;
  let orgUsername: string;

  before(async () => {
    db = getDatabase();
    app = express();
    app.use(express.json());
    app.use('/api', createApiRouter(db));

    testOrgId = 'org-test-' + crypto.randomUUID().substring(0, 6);
    const now = new Date().toISOString();

    // Create test organization
    db.prepare('INSERT INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run(testOrgId, 'Test Vendor Org', now);
    db.prepare('INSERT OR IGNORE INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run('org-sysadmin-internal', 'Internal Admin Org', now);

    // Login as SYS_ADMIN (seeded default)
    const sysLoginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'sysadmin', password: 'SysAdmin123!' });
    assert.strictEqual(sysLoginRes.status, 200);
    sysAdminToken = sysLoginRes.body.token;
    assert.ok(sysAdminToken);

    // Create ORG_ADMIN user (should be forbidden from admin API)
    const orgUserId = 'user-orgadmin-' + crypto.randomUUID().substring(0, 6);
    orgUsername = 'orgadmin_' + crypto.randomUUID().substring(0, 6);
    const orgHash = hashPassword('OrgAdmin123!');
    db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      orgUserId, testOrgId, orgUsername, orgHash, 'ORG_ADMIN', now
    );

    // Login as ORG_ADMIN
    const orgLoginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: orgUsername, password: 'OrgAdmin123!' });
    assert.strictEqual(orgLoginRes.status, 200);
    orgAdminToken = orgLoginRes.body.token;
    assert.ok(orgAdminToken);
  });

  it('1. Enforces strict RBAC: ORG_ADMIN is forbidden from accessing admin API', async () => {
    const res = await request(app)
      .get('/api/admin/organizations')
      .set('Authorization', `Bearer ${orgAdminToken}`);
    assert.strictEqual(res.status, 403);
  });

  it('2. Allows SYS_ADMIN to access organizations search and details', async () => {
    const res = await request(app)
      .get('/api/admin/organizations')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
    const found = res.body.find((o: any) => o.org_id === testOrgId);
    assert.ok(found);

    const detailRes = await request(app)
      .get(`/api/admin/organizations/${testOrgId}`)
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(detailRes.status, 200);
    assert.strictEqual(detailRes.body.organization.org_id, testOrgId);
  });

  it('3. Allows SYS_ADMIN to suspend and reactivate an organization', async () => {
    const suspendRes = await request(app)
      .post(`/api/admin/organizations/${testOrgId}/suspend`)
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(suspendRes.status, 200);
    assert.strictEqual(suspendRes.body.success, true);

    const reactivateRes = await request(app)
      .post(`/api/admin/organizations/${testOrgId}/reactivate`)
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(reactivateRes.status, 200);
    assert.strictEqual(reactivateRes.body.success, true);
  });

  it('4. Allows SYS_ADMIN to view users and perform password reset recovery workflow', async () => {
    const usersRes = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(usersRes.status, 200);
    assert.ok(usersRes.body.length > 0);

    const targetUser = usersRes.body.find((u: any) => u.username === orgUsername);
    assert.ok(targetUser);

    const resetRes = await request(app)
      .post(`/api/admin/users/${targetUser.user_id}/reset-recovery`)
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(resetRes.status, 200);
    assert.ok(resetRes.body.temporary_password);
  });

  it('5. Allows SYS_ADMIN to issue licenses and view subscriptions, usage, security events, and system info', async () => {
    const issueRes = await request(app)
      .post('/api/admin/licenses/issue')
      .set('Authorization', `Bearer ${sysAdminToken}`)
      .send({
        organization_id: testOrgId,
        plan_id: 'plan-enterprise',
        duration_days: 180
      });
    if (issueRes.status !== 200) {
      console.log('Issue License Failed:', issueRes.status, issueRes.body);
    }
    assert.strictEqual(issueRes.status, 200);
    assert.ok(issueRes.body.license_id);

    const subsRes = await request(app)
      .get('/api/admin/subscriptions')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(subsRes.status, 200);

    const usageRes = await request(app)
      .get('/api/admin/usage')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(usageRes.status, 200);
    assert.ok(usageRes.body.total_organizations >= 1);

    const securityRes = await request(app)
      .get('/api/admin/security/events')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(securityRes.status, 200);
    assert.ok(Array.isArray(securityRes.body));

    const systemRes = await request(app)
      .get('/api/admin/system/info')
      .set('Authorization', `Bearer ${sysAdminToken}`);
    assert.strictEqual(systemRes.status, 200);
    assert.strictEqual(systemRes.body.current_application_version, '8.3.0');
  });

  after(() => {
    process.exit(0);
  });
});
