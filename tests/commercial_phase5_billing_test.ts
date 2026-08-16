import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { getDatabase } from '../backend/db.ts';
import { BillingService, RazorpayWebhookPayload } from '../backend/billing.ts';
import { LicensingEngine } from '../backend/licensing.ts';

test('COMMERCIALIZATION PHASE 5: Subscription Billing & Webhook Synchronization', async (t) => {
  const db = getDatabase(':memory:');
  const licensingEngine = new LicensingEngine(db);
  const testSecret = 'test_webhook_secret_key_12345';
  const billingService = new BillingService(db, licensingEngine, {
    gracePeriodDays: 7,
    webhookSecret: testSecret
  });

  const orgA = 'org_test_billing_alpha_' + Date.now();
  const orgB = 'org_test_billing_beta_' + Date.now();
  const now = new Date().toISOString();

  // Setup test organizations
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(
    orgA, 'Alpha Corp', now
  );
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(
    orgB, 'Beta Security', now
  );

  await t.test('1. Central Plan Configuration & Matrix', () => {
    const plans = billingService.getAllPlans();
    assert.strictEqual(plans.length, 3, 'Should have exactly 3 centralized plans');

    const trial = billingService.getPlanConfig('TRIAL');
    assert.ok(trial, 'TRIAL plan should exist');
    assert.strictEqual(trial.pricing.monthly_inr, 0);
    assert.strictEqual(trial.pricing.trial_days, 14);

    const pro = billingService.getPlanConfig('PROFESSIONAL');
    assert.ok(pro, 'PROFESSIONAL plan should exist');
    assert.strictEqual(pro.pricing.monthly_inr, 499900);
    assert.strictEqual(pro.max_devices, 10);

    const ent = billingService.getPlanConfig('ENTERPRISE');
    assert.ok(ent, 'ENTERPRISE plan should exist');
    assert.strictEqual(ent.scan_limit, -1);
  });

  await t.test('2. Subscription Checkout Intent & Trial Setup', () => {
    const checkout = billingService.createSubscriptionCheckout(orgA, 'admin@alphacorp.com', 'TRIAL', 'MONTHLY');
    assert.strictEqual(checkout.status, 'TRIAL');
    assert.ok(checkout.subscription_id);
    assert.ok(checkout.provider_subscription_id);

    const billingState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(billingState.subscription?.status, 'TRIAL');
    assert.strictEqual(billingState.license_status, 'TRIAL');
    assert.strictEqual(billingState.license_valid, true);
  });

  await t.test('3. Webhook Signature Verification & Forged Signatures Rejection', () => {
    const payloadStr = JSON.stringify({ event: 'payment.captured', test: true });
    const validSignature = crypto.createHmac('sha256', testSecret).update(payloadStr).digest('hex');
    const invalidSignature = crypto.createHmac('sha256', 'wrong_secret').update(payloadStr).digest('hex');

    assert.strictEqual(billingService.verifyWebhookSignature(payloadStr, validSignature), true, 'Valid HMAC signature should pass');
    assert.strictEqual(billingService.verifyWebhookSignature(payloadStr, invalidSignature), false, 'Forged HMAC signature must fail');
    assert.strictEqual(billingService.verifyWebhookSignature(payloadStr, 'arbitrary_garbage'), false, 'Corrupted signature must fail');
  });

  await t.test('4. Successful Webhook Payment -> Subscription ACTIVE -> License Synchronized', () => {
    const billingState = billingService.getOrganizationBillingState(orgA);
    const rzpSubId = billingState.subscription?.subscription_id;

    // Fetch provider sub id
    const subRecord = db.prepare('SELECT provider_subscription_id FROM subscriptions WHERE subscription_id = ?').get(rzpSubId) as any;
    const providerSubId = subRecord.provider_subscription_id;

    const eventId = 'evt_pay_captured_' + Date.now();
    const webhookPayload: RazorpayWebhookPayload = {
      entity: 'event',
      event: 'payment.captured',
      contains: ['payment', 'subscription'],
      payload: {
        payment: {
          entity: {
            id: 'pay_rzp_mock_123',
            entity: 'payment',
            amount: 499900,
            currency: 'INR',
            status: 'captured',
            created_at: Math.floor(Date.now() / 1000)
          }
        },
        subscription: {
          entity: {
            id: providerSubId,
            entity: 'subscription',
            plan_id: 'plan-professional',
            customer_id: 'cust_rzp_123',
            status: 'active',
            current_start: Math.floor(Date.now() / 1000),
            current_end: Math.floor((Date.now() + 30 * 86400000) / 1000)
          }
        }
      },
      created_at: Math.floor(Date.now() / 1000)
    };

    const rawBody = JSON.stringify(webhookPayload);
    const signature = crypto.createHmac('sha256', testSecret).update(rawBody).digest('hex');

    const result = billingService.processWebhook(eventId, rawBody, signature, webhookPayload);
    assert.strictEqual(result.status, 'PROCESSED');

    // Verify Subscription status
    const updatedState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(updatedState.subscription?.status, 'ACTIVE');
    assert.strictEqual(updatedState.license_status, 'ACTIVE');
    assert.strictEqual(updatedState.license_valid, true);

    // Verify Payment Log
    assert.strictEqual(updatedState.recent_payments.length, 1);
    assert.strictEqual(updatedState.recent_payments[0].status, 'SUCCESS');
    assert.strictEqual(updatedState.recent_payments[0].amount_formatted, '4999.00');
  });

  await t.test('5. Webhook Replay Protection & Idempotency', () => {
    const eventId = 'evt_replay_test_' + Date.now();
    const webhookPayload: RazorpayWebhookPayload = {
      entity: 'event',
      event: 'subscription.charged',
      contains: ['subscription'],
      payload: {
        subscription: {
          entity: {
            id: 'sub_dummy_mock',
            entity: 'subscription',
            plan_id: 'plan-professional',
            customer_id: 'cust_dummy',
            status: 'active',
            current_start: Math.floor(Date.now() / 1000),
            current_end: Math.floor((Date.now() + 30 * 86400000) / 1000)
          }
        }
      },
      created_at: Math.floor(Date.now() / 1000)
    };

    const rawBody = JSON.stringify(webhookPayload);
    const signature = crypto.createHmac('sha256', testSecret).update(rawBody).digest('hex');

    // First insertion into processed_webhooks
    db.prepare('INSERT INTO processed_webhooks (event_id, provider, event_type, processed_at) VALUES (?, ?, ?, ?)').run(
      eventId, 'RAZORPAY', 'subscription.charged', new Date().toISOString()
    );

    // Processing same event must return DUPLICATE without re-executing
    const replayResult = billingService.processWebhook(eventId, rawBody, signature, webhookPayload);
    assert.strictEqual(replayResult.status, 'DUPLICATE', 'Replayed event must return DUPLICATE');
  });

  await t.test('6. Payment Failure -> PAST_DUE & Non-Destructive Grace Period Transition', () => {
    const subRecord = db.prepare('SELECT provider_subscription_id FROM subscriptions WHERE org_id = ?').get(orgA) as any;
    const providerSubId = subRecord.provider_subscription_id;

    const eventId = 'evt_pay_failed_' + Date.now();
    const webhookPayload: RazorpayWebhookPayload = {
      entity: 'event',
      event: 'payment.failed',
      contains: ['payment', 'subscription'],
      payload: {
        payment: {
          entity: {
            id: 'pay_rzp_failed_999',
            entity: 'payment',
            amount: 499900,
            currency: 'INR',
            status: 'failed',
            error_code: 'PAYMENT_CARD_DECLINED',
            error_description: 'Card issuer rejected transaction',
            created_at: Math.floor(Date.now() / 1000)
          }
        },
        subscription: {
          entity: {
            id: providerSubId,
            entity: 'subscription',
            plan_id: 'plan-professional',
            customer_id: 'cust_rzp_123',
            status: 'pending',
            current_start: Math.floor(Date.now() / 1000),
            current_end: Math.floor((Date.now() + 30 * 86400000) / 1000)
          }
        }
      },
      created_at: Math.floor(Date.now() / 1000)
    };

    const rawBody = JSON.stringify(webhookPayload);
    const signature = crypto.createHmac('sha256', testSecret).update(rawBody).digest('hex');

    const result = billingService.processWebhook(eventId, rawBody, signature, webhookPayload);
    assert.strictEqual(result.status, 'PROCESSED');

    const pastDueState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(pastDueState.subscription?.status, 'PAST_DUE');
    assert.ok(pastDueState.subscription?.grace_until, 'Grace period until timestamp must be set');
    assert.strictEqual(pastDueState.license_status, 'PAST_DUE');
    assert.strictEqual(pastDueState.license_valid, true, 'License must remain valid during grace period (non-destructive)');
  });

  await t.test('7. Plan Upgrade & Downgrade Synchronization', () => {
    const upgradeRes = billingService.changeSubscriptionPlan(orgA, 'ENTERPRISE', 'ANNUAL');
    assert.strictEqual(upgradeRes.success, true);
    assert.strictEqual(upgradeRes.action, 'PLAN_UPGRADE');

    const upgradedState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(upgradedState.subscription?.plan_id, 'plan-enterprise');
    assert.strictEqual(upgradedState.subscription?.billing_interval, 'ANNUAL');
    assert.strictEqual(upgradedState.subscription?.status, 'ACTIVE');

    // Downgrade
    const downgradeRes = billingService.changeSubscriptionPlan(orgA, 'PROFESSIONAL', 'MONTHLY');
    assert.strictEqual(downgradeRes.success, true);
    assert.strictEqual(downgradeRes.action, 'PLAN_DOWNGRADE');

    const downgradedState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(downgradedState.subscription?.plan_id, 'plan-professional');
    assert.strictEqual(downgradedState.subscription?.billing_interval, 'MONTHLY');
  });

  await t.test('8. Subscription Cancellation', () => {
    const subRecord = db.prepare('SELECT provider_subscription_id FROM subscriptions WHERE org_id = ?').get(orgA) as any;
    const providerSubId = subRecord.provider_subscription_id;

    const eventId = 'evt_sub_cancelled_' + Date.now();
    const webhookPayload: RazorpayWebhookPayload = {
      entity: 'event',
      event: 'subscription.cancelled',
      contains: ['subscription'],
      payload: {
        subscription: {
          entity: {
            id: providerSubId,
            entity: 'subscription',
            plan_id: 'plan-professional',
            customer_id: 'cust_rzp_123',
            status: 'cancelled',
            current_start: Math.floor(Date.now() / 1000),
            current_end: Math.floor(Date.now() / 1000)
          }
        }
      },
      created_at: Math.floor(Date.now() / 1000)
    };

    const rawBody = JSON.stringify(webhookPayload);
    const signature = crypto.createHmac('sha256', testSecret).update(rawBody).digest('hex');

    const result = billingService.processWebhook(eventId, rawBody, signature, webhookPayload);
    assert.strictEqual(result.status, 'PROCESSED');

    const cancelledState = billingService.getOrganizationBillingState(orgA);
    assert.strictEqual(cancelledState.subscription?.status, 'CANCELLED');
    assert.strictEqual(cancelledState.license_status, 'CANCELLED');
    assert.strictEqual(cancelledState.license_valid, false);
  });

  await t.test('9. Cross-Tenant Billing Isolation', () => {
    // Org B has no subscriptions yet
    const orgBState = billingService.getOrganizationBillingState(orgB);
    assert.strictEqual(orgBState.organization_id, orgB);
    assert.strictEqual(orgBState.subscription, null);
    assert.strictEqual(orgBState.recent_payments.length, 0);

    // Verify Org B cannot see Org A payment records
    const orgAPaymentsInOrgB = db.prepare('SELECT * FROM payment_events WHERE org_id = ?').all(orgB);
    assert.strictEqual(orgAPaymentsInOrgB.length, 0);
  });
});
