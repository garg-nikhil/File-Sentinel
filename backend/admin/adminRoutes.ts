import { Router } from 'express';
import type { Request, Response } from 'express';
import { authenticateRequest, requireRole, logSecurityEvent } from '../auth.js';
import { AdminService } from './adminService.js';
import { PilotService } from '../pilotService.js';

export function createAdminRouter(db: any): Router {
  const router = Router();
  const adminService = new AdminService(db);
  const pilotService = new PilotService(db);

  // Apply authentication & strict SYS_ADMIN role requirement to ALL admin routes
  router.use(authenticateRequest);
  router.use(requireRole(['SYS_ADMIN']));

  // --- CONTROLLED PILOT ADMINISTRATION ---
  router.get('/pilots', (req: Request, res: Response) => {
    try {
      const pilots = pilotService.listPilots();
      res.json(pilots);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/pilots/create', (req: Request, res: Response) => {
    try {
      const { org_name, admin_username, admin_password, duration_days } = req.body;
      if (!org_name || !admin_username) {
        return res.status(400).json({ error: 'org_name and admin_username are required' });
      }
      const result = pilotService.createPilotOrganization({
        org_name,
        admin_username,
        admin_password,
        duration_days: duration_days ? Number(duration_days) : 14,
        admin_user_id: req.user!.userId
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/pilots/:org_id/extend', (req: Request, res: Response) => {
    try {
      const { additional_days } = req.body;
      const result = pilotService.extendPilotTrial(req.params.org_id, Number(additional_days || 14), req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/pilots/:org_id/convert', (req: Request, res: Response) => {
    try {
      const { plan_id } = req.body;
      if (!plan_id) return res.status(400).json({ error: 'plan_id is required' });
      const result = pilotService.convertPilotToPaid(req.params.org_id, plan_id, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/pilots/telemetry', (req: Request, res: Response) => {
    try {
      const events = db.prepare('SELECT * FROM pilot_telemetry_events ORDER BY timestamp DESC LIMIT 200').all();
      res.json(events);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Organizations
  router.get('/organizations', (req: Request, res: Response) => {
    try {
      const search = req.query.search as string | undefined;
      const orgs = adminService.searchOrganizations(search);
      res.json(orgs);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/organizations/:org_id', (req: Request, res: Response) => {
    try {
      const details = adminService.getOrganizationDetails(req.params.org_id);
      if (!details) {
        return res.status(404).json({ error: 'Organization not found' });
      }
      res.json(details);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/organizations/:org_id/suspend', (req: Request, res: Response) => {
    try {
      const result = adminService.suspendOrganization(req.params.org_id, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/organizations/:org_id/reactivate', (req: Request, res: Response) => {
    try {
      const result = adminService.reactivateOrganization(req.params.org_id, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Users
  router.get('/users', (req: Request, res: Response) => {
    try {
      const users = adminService.listUsers();
      res.json(users);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/users/:user_id/disable', (req: Request, res: Response) => {
    try {
      const { disabled } = req.body;
      const result = adminService.setUserDisabled(req.params.user_id, disabled ? 1 : 0, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/users/:user_id/reset-recovery', (req: Request, res: Response) => {
    try {
      const result = adminService.resetUserPassword(req.params.user_id, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Devices
  router.get('/devices', (req: Request, res: Response) => {
    try {
      const devices = adminService.listDevices();
      res.json(devices);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/devices/:device_id/revoke', (req: Request, res: Response) => {
    try {
      const { revoked } = req.body;
      const result = adminService.setDeviceRevoked(req.params.device_id, revoked ? 1 : 0, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Licenses
  router.get('/licenses', (req: Request, res: Response) => {
    try {
      const licenses = adminService.listLicenses();
      res.json(licenses);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/licenses/issue', (req: Request, res: Response) => {
    try {
      const { organization_id, plan_id, status, duration_days, max_users, max_devices, scan_limit } = req.body;
      if (!organization_id || !plan_id) {
        return res.status(400).json({ error: 'organization_id and plan_id are required' });
      }
      const result = adminService.issueLicense({
        organization_id,
        plan_id,
        status,
        duration_days,
        max_users,
        max_devices,
        scan_limit,
        admin_user_id: req.user!.userId
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/licenses/:license_id/status', (req: Request, res: Response) => {
    try {
      const { status } = req.body;
      if (!['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
      }
      const result = adminService.updateLicenseStatus(req.params.license_id, status, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/licenses/:license_id/extend', (req: Request, res: Response) => {
    try {
      const { additional_days } = req.body;
      const result = adminService.extendLicense(req.params.license_id, Number(additional_days || 30), req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/licenses/:license_id/plan', (req: Request, res: Response) => {
    try {
      const { plan_id } = req.body;
      if (!plan_id) return res.status(400).json({ error: 'plan_id is required' });
      const result = adminService.changeLicensePlan(req.params.license_id, plan_id, req.user!.userId);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Subscriptions
  router.get('/subscriptions', (req: Request, res: Response) => {
    try {
      const subs = adminService.listSubscriptions();
      res.json(subs);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Usage & Telemetry
  router.get('/usage', (req: Request, res: Response) => {
    try {
      const usage = adminService.getUsageOverview();
      res.json(usage);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Security Monitoring
  router.get('/security/events', (req: Request, res: Response) => {
    try {
      const eventType = req.query.event_type as string | undefined;
      const limit = req.query.limit ? Number(req.query.limit) : 100;
      const events = adminService.listSecurityEvents({ event_type: eventType, limit });
      res.json(events);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // System Version & Updates
  router.get('/system/info', (req: Request, res: Response) => {
    try {
      const info = adminService.getSystemInfo();
      res.json(info);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}
