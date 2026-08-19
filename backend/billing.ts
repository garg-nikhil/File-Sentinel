import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { getDatabase } from './db.js';
import { LicensingEngine, LicenseStatus } from './licensing.js';

export type BillingInterval = 'MONTHLY' | 'ANNUAL';

export type SubscriptionStatus =
  | 'TRIAL'
  | 'ACTIVE'
  | 'PAST_DUE'
  | 'GRACE_PERIOD'
  | 'EXPIRED'
  | 'CANCELLED';

export interface PlanPricing {
  monthly_inr: number;
  annual_inr: number;
  currency: string;
  trial_days: number;
}

export interface PlanDefinition {
  plan_id: string;
  name: string;
  pricing: PlanPricing;
  max_users: number;
  max_devices: number;
  scan_limit: number; // -1 for unlimited
  feature_flags: string[];
}

export const CENTRAL_PLAN_CONFIG: Record<string, PlanDefinition> = {
  'TRIAL': {
    plan_id: 'plan-starter-trial',
    name: 'Starter Trial',
    pricing: {
      monthly_inr: 0,
      annual_inr: 0,
      currency: 'INR',
      trial_days: 14
    },
    max_users: 2,
    max_devices: 2,
    scan_limit: 25,
    feature_flags: ['LOCAL_SCANNING', 'AUDIT_ENGINE']
  },
  'PROFESSIONAL': {
    plan_id: 'plan-professional',
    name: 'Professional Compliance',
    pricing: {
      monthly_inr: 499900, // 4,999 INR in paise
      annual_inr: 4999000, // 49,990 INR in paise (2 months free)
      currency: 'INR',
      trial_days: 0
    },
    max_users: 10,
    max_devices: 10,
    scan_limit: 500,
    feature_flags: ['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING']
  },
  'ENTERPRISE': {
    plan_id: 'plan-enterprise',
    name: 'Enterprise Zero-Trust DLP Suite',
    pricing: {
      monthly_inr: 1499900, // 14,999 INR in paise
      annual_inr: 14999000, // 149,990 INR in paise
      currency: 'INR',
      trial_days: 0
    },
    max_users: 100,
    max_devices: 50,
    scan_limit: -1,
    feature_flags: [
      'LOCAL_SCANNING',
      'AUDIT_ENGINE',
      'MULTI_FOLDER_SCAN',
      'CLOUD_EVIDENCE_UPLOAD',
      'CENTRAL_HISTORY',
      'ADVANCED_REPORTING',
      'API_ACCESS'
    ]
  }
};

export interface RazorpayWebhookPayload {
  entity: string;
  account_id?: string;
  event: string;
  contains: string[];
  payload: {
    payment?: {
      entity: {
        id: string;
        entity: string;
        amount: number;
        currency: string;
        status: string;
        order_id?: string;
        invoice_id?: string;
        customer_id?: string;
        error_code?: string;
        error_description?: string;
        created_at: number;
        notes?: Record<string, any>;
      };
    };
    subscription?: {
      entity: {
        id: string;
        entity: string;
        plan_id: string;
        customer_id: string;
        status: string;
        current_start: number;
        current_end: number;
        ended_at?: number;
        charge_at?: number;
        start_at?: number;
        end_at?: number;
        total_count?: number;
        paid_count?: number;
        remaining_count?: number;
        notes?: Record<string, any>;
      };
    };
  };
  created_at: number;
}

export class BillingService {
  private db: DatabaseSync;
  private licensingEngine: LicensingEngine;
  private defaultGracePeriodDays: number;
  private webhookSecret: string;

  constructor(
    db?: DatabaseSync,
    licensingEngine?: LicensingEngine,
    options?: { gracePeriodDays?: number; webhookSecret?: string }
  ) {
    this.db = db || getDatabase();
    this.licensingEngine = licensingEngine || new LicensingEngine(this.db);
    this.defaultGracePeriodDays = options?.gracePeriodDays ?? 7;
    this.webhookSecret = options?.webhookSecret || process.env.RAZORPAY_WEBHOOK_SECRET || 'filesentinel-webhook-secret-secure-2026';
  }

  public getPlanConfig(planKey: string): PlanDefinition | null {
    const key = planKey.toUpperCase();
    if (CENTRAL_PLAN_CONFIG[key]) return CENTRAL_PLAN_CONFIG[key];
    // Try matching by plan_id
    for (const p of Object.values(CENTRAL_PLAN_CONFIG)) {
      if (p.plan_id === planKey) return p;
    }
    return null;
  }

  public getAllPlans(): PlanDefinition[] {
    return Object.values(CENTRAL_PLAN_CONFIG);
  }

  /**
   * Generates or retrieves customer profile for an organization
   */
  public getOrCreateCustomer(orgId: string, email: string, name?: string): { customer_id: string; provider_customer_id: string } {
    const existing = this.db.prepare('SELECT * FROM billing_customers WHERE org_id = ?').get(orgId) as any;
    if (existing) {
      return {
        customer_id: existing.customer_id,
        provider_customer_id: existing.provider_customer_id
      };
    }

    const customerId = 'cust-' + crypto.randomBytes(8).toString('hex');
    const providerCustomerId = 'cust_rzp_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO billing_customers (customer_id, org_id, provider, provider_customer_id, email, name, billing_currency, created_at, updated_at)
      VALUES (?, ?, 'RAZORPAY', ?, ?, ?, 'INR', ?, ?)
    `).run(customerId, orgId, providerCustomerId, email, name || 'Customer', now, now);

    return { customer_id: customerId, provider_customer_id: providerCustomerId };
  }

  /**
   * Initializes a subscription order/intent for an organization
   */
  public createSubscriptionCheckout(
    orgId: string,
    email: string,
    planKey: 'TRIAL' | 'PROFESSIONAL' | 'ENTERPRISE',
    interval: BillingInterval = 'MONTHLY'
  ) {
    const plan = this.getPlanConfig(planKey);
    if (!plan) {
      throw new Error(`Invalid plan key: ${planKey}`);
    }

    const customer = this.getOrCreateCustomer(orgId, email);
    const subId = 'sub-' + crypto.randomBytes(8).toString('hex');
    const rzpSubId = 'sub_rzp_' + crypto.randomBytes(10).toString('hex');
    const now = new Date();
    const nowIso = now.toISOString();

    let durationDays = interval === 'ANNUAL' ? 365 : 30;
    let initialStatus: SubscriptionStatus = planKey === 'TRIAL' ? 'TRIAL' : 'ACTIVE';
    let trialEndsAt: string | null = null;

    if (planKey === 'TRIAL') {
      durationDays = plan.pricing.trial_days || 14;
      trialEndsAt = new Date(now.getTime() + durationDays * 86400000).toISOString();
    }

    const periodEnd = new Date(now.getTime() + durationDays * 86400000).toISOString();

    this.db.prepare(`
      INSERT INTO subscriptions (
        subscription_id, org_id, customer_id, provider_subscription_id,
        plan_id, billing_interval, status, current_period_start, current_period_end,
        grace_until, trial_ends_at, cancel_at_period_end, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 0, ?, ?)
    `).run(
      subId,
      orgId,
      customer.customer_id,
      rzpSubId,
      plan.plan_id,
      interval,
      initialStatus,
      nowIso,
      periodEnd,
      trialEndsAt,
      nowIso,
      nowIso
    );

    // Sync license directly for trial or created subscription
    this.synchronizeLicenseFromSubscription(orgId, plan.plan_id, initialStatus, nowIso, periodEnd);

    this.logSubscriptionEvent(subId, orgId, 'SUBSCRIPTION_CREATED', null, initialStatus, {
      plan_id: plan.plan_id,
      interval,
      provider_subscription_id: rzpSubId
    });

    return {
      subscription_id: subId,
      provider_subscription_id: rzpSubId,
      plan_name: plan.name,
      interval,
      amount: interval === 'ANNUAL' ? plan.pricing.annual_inr : plan.pricing.monthly_inr,
      currency: plan.pricing.currency,
      status: initialStatus,
      current_period_end: periodEnd
    };
  }

  /**
   * Verifies Razorpay Webhook HMAC-SHA256 Signature
   */
  public verifyWebhookSignature(rawBody: string, signature: string, secret?: string): boolean {
    const key = secret || this.webhookSecret;
    if (!signature || !rawBody) return false;
    try {
      const expectedSignature = crypto
        .createHmac('sha256', key)
        .update(rawBody)
        .digest('hex');
      return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
    } catch {
      return false;
    }
  }

  /**
   * Process Razorpay Webhook Event with Idempotency & Replay Protection
   */
  public processWebhook(
    eventId: string,
    rawBody: string,
    signature: string,
    parsedPayload: RazorpayWebhookPayload
  ): { status: 'PROCESSED' | 'DUPLICATE' | 'IGNORED' | 'ERROR'; message: string; sub_id?: string } {
    // 1. Signature Verification
    if (!this.verifyWebhookSignature(rawBody, signature)) {
      throw new Error('Invalid Razorpay webhook signature');
    }

    // 2. Replay Protection & Idempotency Check
    const existing = this.db.prepare('SELECT event_id FROM processed_webhooks WHERE event_id = ?').get(eventId);
    if (existing) {
      return {
        status: 'DUPLICATE',
        message: `Webhook event ${eventId} already processed (idempotent ignore)`
      };
    }

    const eventType = parsedPayload.event;
    const nowIso = new Date().toISOString();

    try {
      // 3. Dispatch specific event handlers
      if (eventType === 'subscription.charged' || eventType === 'payment.captured') {
        this.handlePaymentSuccess(parsedPayload, eventId);
      } else if (eventType === 'payment.failed') {
        this.handlePaymentFailure(parsedPayload, eventId);
      } else if (eventType === 'subscription.cancelled') {
        this.handleSubscriptionCancelled(parsedPayload, eventId);
      } else if (eventType === 'subscription.paused' || eventType === 'subscription.pending') {
        this.handleSubscriptionPastDue(parsedPayload, eventId);
      } else if (eventType === 'subscription.resumed' || eventType === 'subscription.activated') {
        this.handleSubscriptionActivated(parsedPayload, eventId);
      }

      // Record event as processed in audit table
      this.db.prepare(`
        INSERT INTO processed_webhooks (event_id, provider, event_type, processed_at)
        VALUES (?, 'RAZORPAY', ?, ?)
      `).run(eventId, eventType, nowIso);

      return {
        status: 'PROCESSED',
        message: `Successfully processed event ${eventType}`
      };
    } catch (err: any) {
      return {
        status: 'ERROR',
        message: err.message || 'Error processing webhook event'
      };
    }
  }

  /**
   * Handles successful payment charge event
   */
  private handlePaymentSuccess(payload: RazorpayWebhookPayload, eventId: string) {
    const payment = payload.payload.payment?.entity;
    const sub = payload.payload.subscription?.entity;
    const rzpSubId = sub?.id || payment?.notes?.rzp_subscription_id;

    if (!rzpSubId && !payment) {
      throw new Error('Missing subscription identifier in payment.captured webhook payload');
    }

    // Find subscription in DB
    let subRecord: any = null;
    if (rzpSubId) {
      subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE provider_subscription_id = ?').get(rzpSubId);
    }
    if (!subRecord && payment?.notes?.org_id) {
      subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC LIMIT 1').get(payment.notes.org_id);
    }

    if (!subRecord) {
      throw new Error(`Subscription with provider ID ${rzpSubId} not found`);
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const durationDays = subRecord.billing_interval === 'ANNUAL' ? 365 : 30;
    const periodStart = sub?.current_start ? new Date(sub.current_start * 1000).toISOString() : nowIso;
    const periodEnd = sub?.current_end ? new Date(sub.current_end * 1000).toISOString() : new Date(now.getTime() + durationDays * 86400000).toISOString();

    const prevStatus = subRecord.status;
    const newStatus: SubscriptionStatus = 'ACTIVE';

    // Update Subscription
    this.db.prepare(`
      UPDATE subscriptions SET
        status = ?,
        current_period_start = ?,
        current_period_end = ?,
        grace_until = NULL,
        updated_at = ?
      WHERE subscription_id = ?
    `).run(newStatus, periodStart, periodEnd, nowIso, subRecord.subscription_id);

    // Record Payment Event
    if (payment) {
      const paymentId = 'pay-' + crypto.randomBytes(8).toString('hex');
      this.db.prepare(`
        INSERT INTO payment_events (
          payment_id, subscription_id, org_id, provider_payment_id,
          amount_cents, currency, status, raw_payload_json, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', ?, ?)
      `).run(
        paymentId,
        subRecord.subscription_id,
        subRecord.org_id,
        payment.id || ('pay_rzp_' + crypto.randomBytes(6).toString('hex')),
        payment.amount || 0,
        payment.currency || 'INR',
        JSON.stringify(payment),
        nowIso
      );
    }

    // Log Subscription Event
    this.logSubscriptionEvent(subRecord.subscription_id, subRecord.org_id, 'PAYMENT_SUCCESS', prevStatus, newStatus, {
      payment_id: payment?.id,
      period_start: periodStart,
      period_end: periodEnd
    });

    // Synchronize FileSentinel License
    this.synchronizeLicenseFromSubscription(
      subRecord.org_id,
      subRecord.plan_id,
      newStatus,
      periodStart,
      periodEnd
    );
  }

  /**
   * Handles payment failure event: Grace Period transition (non-immediate cutoff)
   */
  private handlePaymentFailure(payload: RazorpayWebhookPayload, eventId: string) {
    const payment = payload.payload.payment?.entity;
    const sub = payload.payload.subscription?.entity;
    const rzpSubId = sub?.id || payment?.notes?.rzp_subscription_id;

    let subRecord: any = null;
    if (rzpSubId) {
      subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE provider_subscription_id = ?').get(rzpSubId);
    }
    if (!subRecord && payment?.notes?.org_id) {
      subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC LIMIT 1').get(payment.notes.org_id);
    }

    if (!subRecord) {
      throw new Error(`Subscription for failed payment not found`);
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const graceUntil = new Date(now.getTime() + this.defaultGracePeriodDays * 86400000).toISOString();

    const prevStatus = subRecord.status;
    const newStatus: SubscriptionStatus = 'PAST_DUE';

    // Update Subscription to PAST_DUE with grace period
    this.db.prepare(`
      UPDATE subscriptions SET
        status = ?,
        grace_until = ?,
        updated_at = ?
      WHERE subscription_id = ?
    `).run(newStatus, graceUntil, nowIso, subRecord.subscription_id);

    // Record Failed Payment Event
    if (payment) {
      const paymentId = 'pay-' + crypto.randomBytes(8).toString('hex');
      this.db.prepare(`
        INSERT INTO payment_events (
          payment_id, subscription_id, org_id, provider_payment_id,
          amount_cents, currency, status, error_code, error_description, raw_payload_json, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'FAILURE', ?, ?, ?, ?)
      `).run(
        paymentId,
        subRecord.subscription_id,
        subRecord.org_id,
        payment.id || ('pay_rzp_' + crypto.randomBytes(6).toString('hex')),
        payment.amount || 0,
        payment.currency || 'INR',
        payment.error_code || 'BAD_REQUEST',
        payment.error_description || 'Transient charge authorization failure',
        JSON.stringify(payment),
        nowIso
      );
    }

    // Log Subscription Event
    this.logSubscriptionEvent(subRecord.subscription_id, subRecord.org_id, 'PAYMENT_FAILURE', prevStatus, newStatus, {
      grace_until: graceUntil,
      error_code: payment?.error_code,
      error_description: payment?.error_description
    });

    // Synchronize License to GRACE_PERIOD status (Do NOT cut off immediately)
    this.synchronizeLicenseFromSubscription(
      subRecord.org_id,
      subRecord.plan_id,
      'PAST_DUE',
      subRecord.current_period_start,
      subRecord.current_period_end,
      graceUntil
    );
  }

  /**
   * Handles subscription cancellation
   */
  private handleSubscriptionCancelled(payload: RazorpayWebhookPayload, eventId: string) {
    const sub = payload.payload.subscription?.entity;
    if (!sub?.id) return;

    const subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE provider_subscription_id = ?').get(sub.id) as any;
    if (!subRecord) return;

    const nowIso = new Date().toISOString();
    const prevStatus = subRecord.status;
    const newStatus: SubscriptionStatus = 'CANCELLED';

    this.db.prepare(`
      UPDATE subscriptions SET
        status = ?,
        cancelled_at = ?,
        updated_at = ?
      WHERE subscription_id = ?
    `).run(newStatus, nowIso, nowIso, subRecord.subscription_id);

    this.logSubscriptionEvent(subRecord.subscription_id, subRecord.org_id, 'SUBSCRIPTION_CANCELLED', prevStatus, newStatus);

    // Cancel license
    const currentLicense = this.licensingEngine.getLicenseForOrg(subRecord.org_id);
    if (currentLicense) {
      this.licensingEngine.updateLicenseStatus(currentLicense.license_id, 'CANCELLED', { reason: 'Razorpay Webhook: Subscription Cancelled' }, 'Razorpay Webhook');
    }
  }

  private handleSubscriptionPastDue(payload: RazorpayWebhookPayload, eventId: string) {
    const sub = payload.payload.subscription?.entity;
    if (!sub?.id) return;
    const subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE provider_subscription_id = ?').get(sub.id) as any;
    if (!subRecord) return;

    const now = new Date();
    const nowIso = now.toISOString();
    const graceUntil = new Date(now.getTime() + this.defaultGracePeriodDays * 86400000).toISOString();

    this.db.prepare(`
      UPDATE subscriptions SET status = 'PAST_DUE', grace_until = ?, updated_at = ? WHERE subscription_id = ?
    `).run(graceUntil, nowIso, subRecord.subscription_id);

    this.logSubscriptionEvent(subRecord.subscription_id, subRecord.org_id, 'SUBSCRIPTION_PAST_DUE', subRecord.status, 'PAST_DUE');

    this.synchronizeLicenseFromSubscription(
      subRecord.org_id,
      subRecord.plan_id,
      'PAST_DUE',
      subRecord.current_period_start,
      subRecord.current_period_end,
      graceUntil
    );
  }

  private handleSubscriptionActivated(payload: RazorpayWebhookPayload, eventId: string) {
    const sub = payload.payload.subscription?.entity;
    if (!sub?.id) return;
    const subRecord = this.db.prepare('SELECT * FROM subscriptions WHERE provider_subscription_id = ?').get(sub.id) as any;
    if (!subRecord) return;

    const nowIso = new Date().toISOString();
    this.db.prepare(`
      UPDATE subscriptions SET status = 'ACTIVE', grace_until = NULL, updated_at = ? WHERE subscription_id = ?
    `).run(nowIso, subRecord.subscription_id);

    this.logSubscriptionEvent(subRecord.subscription_id, subRecord.org_id, 'SUBSCRIPTION_ACTIVATED', subRecord.status, 'ACTIVE');

    this.synchronizeLicenseFromSubscription(
      subRecord.org_id,
      subRecord.plan_id,
      'ACTIVE',
      subRecord.current_period_start,
      subRecord.current_period_end
    );
  }

  /**
   * Plan Upgrade / Downgrade support
   */
  public changeSubscriptionPlan(
    orgId: string,
    newPlanKey: 'TRIAL' | 'PROFESSIONAL' | 'ENTERPRISE',
    interval?: BillingInterval
  ) {
    const newPlan = this.getPlanConfig(newPlanKey);
    if (!newPlan) throw new Error(`Unknown plan ${newPlanKey}`);

    const subRecord = this.db.prepare(`
      SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC LIMIT 1
    `).get(orgId) as any;

    if (!subRecord) {
      throw new Error('No active subscription found to modify');
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const newInterval = interval || subRecord.billing_interval;
    const durationDays = newInterval === 'ANNUAL' ? 365 : 30;
    const periodEnd = new Date(now.getTime() + durationDays * 86400000).toISOString();

    const oldPlan = this.getPlanConfig(subRecord.plan_id) || CENTRAL_PLAN_CONFIG['TRIAL'];
    const oldTierWeight = oldPlan.plan_id.includes('enterprise') ? 3 : (oldPlan.plan_id.includes('professional') ? 2 : 1);
    const newTierWeight = newPlan.plan_id.includes('enterprise') ? 3 : (newPlan.plan_id.includes('professional') ? 2 : 1);
    const isUpgrade = newTierWeight > oldTierWeight || (newTierWeight === oldTierWeight && newPlan.max_devices > oldPlan.max_devices);
    const eventType = isUpgrade ? 'PLAN_UPGRADE' : 'PLAN_DOWNGRADE';

    this.db.prepare(`
      UPDATE subscriptions SET
        plan_id = ?,
        billing_interval = ?,
        status = 'ACTIVE',
        current_period_start = ?,
        current_period_end = ?,
        grace_until = NULL,
        updated_at = ?
      WHERE subscription_id = ?
    `).run(newPlan.plan_id, newInterval, nowIso, periodEnd, nowIso, subRecord.subscription_id);

    this.logSubscriptionEvent(subRecord.subscription_id, orgId, eventType, subRecord.status, 'ACTIVE', {
      old_plan_id: subRecord.plan_id,
      new_plan_id: newPlan.plan_id,
      interval: newInterval
    });

    this.synchronizeLicenseFromSubscription(orgId, newPlan.plan_id, 'ACTIVE', nowIso, periodEnd);

    return {
      success: true,
      action: eventType,
      plan_id: newPlan.plan_id,
      plan_name: newPlan.name,
      interval: newInterval,
      period_end: periodEnd
    };
  }

  /**
   * Synchronizes FileSentinel license authoritative record with subscription state
   */
  public synchronizeLicenseFromSubscription(
    orgId: string,
    planId: string,
    subStatus: SubscriptionStatus,
    periodStart: string,
    periodEnd: string,
    graceUntil?: string | null
  ) {
    const plan = this.getPlanConfig(planId);
    if (!plan) return;

    let licenseStatus: LicenseStatus = 'ACTIVE';
    if (subStatus === 'TRIAL') licenseStatus = 'TRIAL';
    else if (subStatus === 'PAST_DUE') licenseStatus = 'PAST_DUE';
    else if (subStatus === 'GRACE_PERIOD') licenseStatus = 'GRACE_PERIOD';
    else if (subStatus === 'EXPIRED') licenseStatus = 'EXPIRED';
    else if (subStatus === 'CANCELLED') licenseStatus = 'CANCELLED';

    const existingLicense = this.licensingEngine.getLicenseForOrg(orgId);
    const nowIso = new Date().toISOString();

    if (existingLicense) {
      this.db.prepare(`
        UPDATE licenses SET
          plan_id = ?,
          status = ?,
          starts_at = ?,
          expires_at = ?,
          grace_until = ?,
          max_users = ?,
          max_devices = ?,
          scan_limit = ?,
          feature_flags = ?,
          updated_at = ?
        WHERE license_id = ?
      `).run(
        plan.plan_id,
        licenseStatus,
        periodStart,
        periodEnd,
        graceUntil || null,
        plan.max_users,
        plan.max_devices,
        plan.scan_limit,
        JSON.stringify(plan.feature_flags),
        nowIso,
        existingLicense.license_id
      );

      this.licensingEngine.logLicenseEvent(
        existingLicense.license_id,
        orgId,
        'LICENSE_SYNC_FROM_BILLING',
        { status: licenseStatus, plan_id: plan.plan_id, expires_at: periodEnd, grace_until: graceUntil }
      );
    } else {
      const licId = 'lic-' + crypto.randomBytes(8).toString('hex');
      this.db.prepare(`
        INSERT INTO licenses (
          license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
          grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
      `).run(
        licId,
        orgId,
        plan.plan_id,
        licenseStatus,
        nowIso,
        periodStart,
        periodEnd,
        graceUntil || null,
        plan.max_users,
        plan.max_devices,
        plan.scan_limit,
        JSON.stringify(plan.feature_flags),
        nowIso,
        nowIso
      );
    }
  }

  /**
   * Retrieves organization billing status (Clean, safe client representation)
   */
  public getOrganizationBillingState(orgId: string) {
    const customer = this.db.prepare('SELECT * FROM billing_customers WHERE org_id = ?').get(orgId) as any;
    const sub = this.db.prepare('SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC LIMIT 1').get(orgId) as any;
    const license = this.licensingEngine.getLicenseForOrg(orgId);
    const licenseValidation = this.licensingEngine.validateLicense(orgId);

    const plan = sub ? this.getPlanConfig(sub.plan_id) : (license ? this.getPlanConfig(license.plan_id) : CENTRAL_PLAN_CONFIG['TRIAL']);

    const payments = this.db.prepare(`
      SELECT payment_id, provider_payment_id, amount_cents, currency, status, processed_at
      FROM payment_events
      WHERE org_id = ?
      ORDER BY processed_at DESC
      LIMIT 10
    `).all(orgId) as any[];

    return {
      organization_id: orgId,
      customer_id: customer?.customer_id,
      customer_email: customer?.email,
      subscription: sub ? {
        subscription_id: sub.subscription_id,
        plan_id: sub.plan_id,
        plan_name: plan?.name || 'Starter Trial',
        billing_interval: sub.billing_interval,
        status: sub.status,
        current_period_start: sub.current_period_start,
        current_period_end: sub.current_period_end,
        grace_until: sub.grace_until,
        trial_ends_at: sub.trial_ends_at,
        cancel_at_period_end: Boolean(sub.cancel_at_period_end)
      } : null,
      license_ui_state: licenseValidation.ui_state,
      license_status: licenseValidation.status,
      license_valid: licenseValidation.valid,
      days_remaining: licenseValidation.days_remaining,
      available_plans: Object.entries(CENTRAL_PLAN_CONFIG).map(([key, val]) => ({
        key,
        plan_id: val.plan_id,
        name: val.name,
        pricing: val.pricing,
        max_users: val.max_users,
        max_devices: val.max_devices,
        scan_limit: val.scan_limit,
        feature_flags: val.feature_flags
      })),
      recent_payments: payments.map(p => ({
        payment_id: p.payment_id,
        amount_formatted: (p.amount_cents / 100).toFixed(2),
        currency: p.currency,
        status: p.status,
        processed_at: p.processed_at
      }))
    };
  }

  public logSubscriptionEvent(
    subId: string,
    orgId: string,
    eventType: string,
    prevStatus: string | null,
    newStatus: string,
    details?: Record<string, any>
  ) {
    const eventId = 'sub-evt-' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO subscription_events (event_id, subscription_id, org_id, event_type, previous_status, new_status, details_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(eventId, subId, orgId, eventType, prevStatus, newStatus, details ? JSON.stringify(details) : null, now);
  }
}
