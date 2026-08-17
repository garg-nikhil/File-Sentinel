/**
 * FILE-SENTINEL — Phase A: Endpoint Compliance Detection Engine
 * Web Access Compliance Detector with False-Positive Defense & Resource Guardrails
 *
 * STRICTLY DETECTION ONLY:
 * - NO network blocking
 * - NO firewall rule modifications
 * - NO proxy configuration changes
 * - NO browser history or personal data inspection
 *
 * LOCAL AGENT ARCHITECTURE:
 * - Note: This detection logic executes on the host endpoint machine running
 *   the FileSentinel backend or local agent daemon.
 * - Read-only HTTPS / DNS probes are conducted strictly for compliance verification.
 */

import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns/promises';
import { URL } from 'node:url';
import {
  WebAccessTarget,
  WebTargetResult,
  WebAccessCategory,
  WebAccessStatus,
  ConfidenceLevel,
  DetectionMethod
} from './endpointTypes.js';

/**
 * Validates whether a hostname belongs to the approved domain registry.
 * Uses exact match or suffix-dot matching to prevent lookalike domains (e.g. evil-facebook.com).
 */
export function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (!hostname || !allowedDomains || allowedDomains.length === 0) {
    return false;
  }
  const cleanHost = hostname.toLowerCase().trim();
  return allowedDomains.some((allowed) => {
    const cleanAllowed = allowed.toLowerCase().trim();
    return cleanHost === cleanAllowed || cleanHost.endsWith('.' + cleanAllowed);
  });
}

/**
 * Validates and sanitizes a custom web access target if configured by an authorized tenant admin.
 * Blocks localhost, private IP ranges, loopback, and metadata-service addresses.
 */
export function validateAndSanitizeTarget(target: Partial<WebAccessTarget>): WebAccessTarget {
  if (!target || typeof target !== 'object') {
    throw new Error('Target definition must be a valid object');
  }

  if (!target.id || typeof target.id !== 'string') {
    throw new Error('Target id is required and must be a string');
  }

  const validCategories: WebAccessCategory[] = ['SOCIAL_MEDIA', 'PERSONAL_EMAIL', 'MESSAGING', 'CLOUD_STORAGE'];
  if (!target.category || !validCategories.includes(target.category)) {
    throw new Error(`Target category must be one of: ${validCategories.join(', ')}`);
  }

  if (!target.service_name || typeof target.service_name !== 'string' || target.service_name.trim().length === 0) {
    throw new Error('Target service_name is required');
  }

  if (!target.probe_url || typeof target.probe_url !== 'string') {
    throw new Error('Target probe_url is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(target.probe_url);
  } catch (err: any) {
    throw new Error(`Invalid probe_url: ${err?.message || 'Malformed URL'}`);
  }

  // Strictly enforce HTTPS protocol
  if (parsed.protocol !== 'https:') {
    throw new Error(`Probe URL protocol must be HTTPS (received ${parsed.protocol})`);
  }

  const host = parsed.hostname.toLowerCase();

  // Prevent probing loopback, localhost, and metadata IP ranges
  const forbiddenHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'];
  if (forbiddenHosts.includes(host) || host.startsWith('127.') || host.startsWith('169.254.')) {
    throw new Error(`Probe URL host '${host}' is forbidden (localhost/metadata prohibited)`);
  }

  // Prevent private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)) {
    throw new Error(`Probe URL host '${host}' is forbidden (private network address prohibited)`);
  }

  const primaryDomain = target.primary_domain?.toLowerCase().trim() || host;
  const expectedIdentifiers = Array.isArray(target.expected_identifiers) && target.expected_identifiers.length > 0
    ? target.expected_identifiers.map(s => String(s).trim())
    : [primaryDomain];

  const allowedDomains = Array.isArray(target.allowed_domains) && target.allowed_domains.length > 0
    ? target.allowed_domains.map(d => String(d).toLowerCase().trim())
    : [primaryDomain];

  return {
    id: target.id.trim(),
    category: target.category,
    service_name: target.service_name.trim(),
    primary_domain: primaryDomain,
    probe_url: target.probe_url.trim(),
    expected_identifiers: expectedIdentifiers,
    allowed_domains: allowedDomains
  };
}

/**
 * Server-controlled default targets with hardened allowed domain registries
 */
export const DEFAULT_WEB_TARGETS: WebAccessTarget[] = [
  // --- SOCIAL MEDIA ---
  {
    id: 'soc-fb',
    category: 'SOCIAL_MEDIA',
    service_name: 'Facebook',
    primary_domain: 'facebook.com',
    probe_url: 'https://www.facebook.com',
    expected_identifiers: ['facebook', 'fb', 'meta'],
    allowed_domains: ['facebook.com', 'fb.com', 'meta.com']
  },
  {
    id: 'soc-ig',
    category: 'SOCIAL_MEDIA',
    service_name: 'Instagram',
    primary_domain: 'instagram.com',
    probe_url: 'https://www.instagram.com',
    expected_identifiers: ['instagram'],
    allowed_domains: ['instagram.com', 'cdninstagram.com']
  },
  {
    id: 'soc-x',
    category: 'SOCIAL_MEDIA',
    service_name: 'X',
    primary_domain: 'x.com',
    probe_url: 'https://x.com',
    expected_identifiers: ['x.com', 'twitter'],
    allowed_domains: ['x.com', 'twitter.com', 'twimg.com']
  },
  {
    id: 'soc-li',
    category: 'SOCIAL_MEDIA',
    service_name: 'LinkedIn',
    primary_domain: 'linkedin.com',
    probe_url: 'https://www.linkedin.com',
    expected_identifiers: ['linkedin'],
    allowed_domains: ['linkedin.com', 'licdn.com']
  },
  {
    id: 'soc-rd',
    category: 'SOCIAL_MEDIA',
    service_name: 'Reddit',
    primary_domain: 'reddit.com',
    probe_url: 'https://www.reddit.com',
    expected_identifiers: ['reddit'],
    allowed_domains: ['reddit.com', 'redd.it']
  },
  {
    id: 'soc-tt',
    category: 'SOCIAL_MEDIA',
    service_name: 'TikTok',
    primary_domain: 'tiktok.com',
    probe_url: 'https://www.tiktok.com',
    expected_identifiers: ['tiktok'],
    allowed_domains: ['tiktok.com', 'tiktokcdn.com']
  },

  // --- PERSONAL EMAIL ---
  {
    id: 'eml-gm',
    category: 'PERSONAL_EMAIL',
    service_name: 'Gmail',
    primary_domain: 'mail.google.com',
    probe_url: 'https://mail.google.com',
    expected_identifiers: ['google', 'gmail', 'accounts.google'],
    allowed_domains: ['google.com', 'googleusercontent.com', 'gstatic.com']
  },
  {
    id: 'eml-yh',
    category: 'PERSONAL_EMAIL',
    service_name: 'Yahoo Mail',
    primary_domain: 'mail.yahoo.com',
    probe_url: 'https://mail.yahoo.com',
    expected_identifiers: ['yahoo', 'login.yahoo'],
    allowed_domains: ['yahoo.com', 'yimg.com']
  },
  {
    id: 'eml-ol',
    category: 'PERSONAL_EMAIL',
    service_name: 'Outlook.com',
    primary_domain: 'outlook.live.com',
    probe_url: 'https://outlook.live.com',
    expected_identifiers: ['outlook', 'live.com', 'microsoft'],
    allowed_domains: ['live.com', 'microsoft.com', 'office.com', 'outlook.com', 'microsoftonline.com']
  },
  {
    id: 'eml-pr',
    category: 'PERSONAL_EMAIL',
    service_name: 'Proton Mail',
    primary_domain: 'mail.proton.me',
    probe_url: 'https://mail.proton.me',
    expected_identifiers: ['proton', 'protonmail'],
    allowed_domains: ['proton.me', 'protonmail.com']
  },
  {
    id: 'eml-ic',
    category: 'PERSONAL_EMAIL',
    service_name: 'iCloud Mail',
    primary_domain: 'www.icloud.com',
    probe_url: 'https://www.icloud.com/mail',
    expected_identifiers: ['icloud', 'apple'],
    allowed_domains: ['icloud.com', 'apple.com']
  },

  // --- MESSAGING ---
  {
    id: 'msg-wa',
    category: 'MESSAGING',
    service_name: 'WhatsApp Web',
    primary_domain: 'web.whatsapp.com',
    probe_url: 'https://web.whatsapp.com',
    expected_identifiers: ['whatsapp'],
    allowed_domains: ['whatsapp.com', 'whatsapp.net']
  },
  {
    id: 'msg-tg',
    category: 'MESSAGING',
    service_name: 'Telegram Web',
    primary_domain: 'web.telegram.org',
    probe_url: 'https://web.telegram.org',
    expected_identifiers: ['telegram'],
    allowed_domains: ['telegram.org', 't.me']
  },
  {
    id: 'msg-ms',
    category: 'MESSAGING',
    service_name: 'Messenger',
    primary_domain: 'www.messenger.com',
    probe_url: 'https://www.messenger.com',
    expected_identifiers: ['messenger', 'facebook'],
    allowed_domains: ['messenger.com', 'facebook.com', 'fb.com', 'meta.com']
  },
  {
    id: 'msg-dc',
    category: 'MESSAGING',
    service_name: 'Discord',
    primary_domain: 'discord.com',
    probe_url: 'https://discord.com',
    expected_identifiers: ['discord'],
    allowed_domains: ['discord.com', 'discord.gg', 'discordapp.com']
  },
  {
    id: 'msg-sg',
    category: 'MESSAGING',
    service_name: 'Signal',
    primary_domain: 'signal.org',
    probe_url: 'https://signal.org',
    expected_identifiers: ['signal'],
    allowed_domains: ['signal.org']
  },

  // --- CLOUD STORAGE ---
  {
    id: 'cld-gd',
    category: 'CLOUD_STORAGE',
    service_name: 'Google Drive',
    primary_domain: 'drive.google.com',
    probe_url: 'https://drive.google.com',
    expected_identifiers: ['google', 'drive', 'accounts.google'],
    allowed_domains: ['google.com', 'googleusercontent.com', 'gstatic.com']
  },
  {
    id: 'cld-db',
    category: 'CLOUD_STORAGE',
    service_name: 'Dropbox',
    primary_domain: 'www.dropbox.com',
    probe_url: 'https://www.dropbox.com',
    expected_identifiers: ['dropbox'],
    allowed_domains: ['dropbox.com', 'dropboxstatic.com']
  },
  {
    id: 'cld-od',
    category: 'CLOUD_STORAGE',
    service_name: 'OneDrive',
    primary_domain: 'onedrive.live.com',
    probe_url: 'https://onedrive.live.com',
    expected_identifiers: ['onedrive', 'live.com', 'microsoft', 'sharepoint'],
    allowed_domains: ['live.com', 'microsoft.com', 'office.com', 'sharepoint.com', 'microsoftonline.com']
  },
  {
    id: 'cld-bx',
    category: 'CLOUD_STORAGE',
    service_name: 'Box',
    primary_domain: 'www.box.com',
    probe_url: 'https://www.box.com',
    expected_identifiers: ['box.com', 'box'],
    allowed_domains: ['box.com', 'boxcdn.net']
  },
  {
    id: 'cld-ic',
    category: 'CLOUD_STORAGE',
    service_name: 'iCloud Drive',
    primary_domain: 'www.icloud.com',
    probe_url: 'https://www.icloud.com/iclouddrive',
    expected_identifiers: ['icloud', 'apple'],
    allowed_domains: ['icloud.com', 'apple.com']
  }
];

export interface WebAccessDetectorOptions {
  targets?: WebAccessTarget[];
  connectionTimeoutMs?: number;
  requestTimeoutMs?: number;
  maxResponseSizeBytes?: number;
  maxRedirects?: number;
  concurrencyLimit?: number;
  mockProbeHandler?: (target: WebAccessTarget) => Promise<WebTargetResult>;
}

export class WebAccessDetector {
  private targets: WebAccessTarget[];
  private connectionTimeoutMs: number;
  private requestTimeoutMs: number;
  private maxResponseSizeBytes: number;
  private maxRedirects: number;
  private concurrencyLimit: number;
  private mockProbeHandler?: (target: WebAccessTarget) => Promise<WebTargetResult>;

  constructor(options: WebAccessDetectorOptions = {}) {
    this.targets = options.targets || DEFAULT_WEB_TARGETS;
    this.connectionTimeoutMs = options.connectionTimeoutMs || 1200;
    this.requestTimeoutMs = options.requestTimeoutMs || 1500;
    this.maxResponseSizeBytes = options.maxResponseSizeBytes || 65536; // 64 KB cap
    this.maxRedirects = options.maxRedirects || 3;
    this.concurrencyLimit = options.concurrencyLimit || 8;
    this.mockProbeHandler = options.mockProbeHandler;
  }

  public getTargets(): WebAccessTarget[] {
    return this.targets;
  }

  /**
   * Run full bounded web accessibility detection across all configured targets
   */
  public async detectAll(): Promise<WebTargetResult[]> {
    const results: WebTargetResult[] = [];
    const queue = [...this.targets];
    const executing: Promise<void>[] = [];

    const runWorker = async () => {
      while (queue.length > 0) {
        const target = queue.shift();
        if (!target) break;
        const result = await this.probeTarget(target);
        results.push(result);
      }
    };

    const workerCount = Math.min(this.concurrencyLimit, this.targets.length);
    for (let i = 0; i < workerCount; i++) {
      executing.push(runWorker());
    }

    await Promise.all(executing);
    return results;
  }

  /**
   * Run detection for a specific category
   */
  public async detectCategory(category: WebAccessCategory): Promise<WebTargetResult[]> {
    const categoryTargets = this.targets.filter(t => t.category === category);
    const results: WebTargetResult[] = [];
    for (const target of categoryTargets) {
      results.push(await this.probeTarget(target));
    }
    return results;
  }

  /**
   * Perform bounded probe on a single target with multi-stage verification
   */
  public async probeTarget(target: WebAccessTarget): Promise<WebTargetResult> {
    const timestamp = new Date().toISOString();

    if (this.mockProbeHandler) {
      return this.mockProbeHandler(target);
    }

    const startTime = Date.now();

    try {
      const parsedUrl = new URL(target.probe_url);

      // Enforce strict HTTPS requirement
      if (parsedUrl.protocol !== 'https:') {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Insecure probe URL protocol '${parsedUrl.protocol}' rejected. Only deterministic HTTPS signals are allowed.`,
          responseTimeMs: Date.now() - startTime,
          timestamp
        };
      }

      // Stage 1: DNS Resolution Check & Sinkhole Detection
      let dnsAddresses: string[] = [];
      try {
        const dnsTimeout = Math.min(this.connectionTimeoutMs, 1200);
        const lookupPromise = dns.lookup(parsedUrl.hostname, { all: true });
        const timerPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('DNS resolution timed out')), dnsTimeout)
        );
        const lookupResult = await Promise.race([lookupPromise, timerPromise]);
        dnsAddresses = lookupResult.map(r => r.address);
      } catch (dnsErr: any) {
        const code = dnsErr?.code;
        const msg = dnsErr?.message || '';
        if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'BLOCKED',
            confidence: 'HIGH',
            detectionMethod: 'DNS_TCP_PROBE',
            reason: 'Domain name resolution blocked or not found (DNS sinkhole / NXDOMAIN)',
            responseTimeMs: Date.now() - startTime,
            timestamp
          };
        }
        if (msg.includes('timed out') || code === 'ETIMEDOUT') {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'UNREACHABLE',
            confidence: 'MEDIUM',
            detectionMethod: 'DNS_TCP_PROBE',
            reason: 'DNS resolution timed out',
            responseTimeMs: Date.now() - startTime,
            timestamp
          };
        }
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'DNS_TCP_PROBE',
          reason: `DNS lookup failed: ${dnsErr?.message || 'Unknown DNS error'}`,
          responseTimeMs: Date.now() - startTime,
          timestamp
        };
      }

      // Check for local DNS Sinkholes (127.0.0.1, 0.0.0.0, etc.)
      const isSinkhole = dnsAddresses.some(addr =>
        addr === '127.0.0.1' ||
        addr === '0.0.0.0' ||
        addr === '::1' ||
        addr === '10.0.0.0' ||
        addr.startsWith('127.')
      );

      if (isSinkhole) {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'BLOCKED',
          confidence: 'HIGH',
          detectionMethod: 'DNS_TCP_PROBE',
          reason: `DNS resolved to loopback sinkhole address: ${dnsAddresses.join(', ')}`,
          responseTimeMs: Date.now() - startTime,
          timestamp
        };
      }

      // Stage 2 & 3: HTTPS Request, TLS Handshake, and Content Inspection
      const httpResult = await this.performBoundedRequest(target.probe_url, target, 0);
      const elapsed = Date.now() - startTime;

      return {
        ...httpResult,
        responseTimeMs: elapsed,
        timestamp
      };
    } catch (err: any) {
      const elapsed = Date.now() - startTime;
      const errMsg = err?.message || '';

      // TLS Interception / Certificate Rejection -> Blocked
      if (/certificate|self-signed|DEPTH_ZERO_SELF_SIGNED_CERT|CERT_AUTHORITY_INVALID|SSL/i.test(errMsg)) {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'BLOCKED',
          confidence: 'HIGH',
          detectionMethod: 'HTTPS_PROBE',
          reason: `TLS handshake intercepted / untrusted corporate cert: ${errMsg}`,
          responseTimeMs: elapsed,
          timestamp
        };
      }

      // Connection refused / reset / timeout
      if (/ECONNREFUSED|ECONNRESET|ETIMEDOUT|timeout/i.test(errMsg)) {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'BLOCKED',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Connection rejected or timed out: ${errMsg}`,
          responseTimeMs: elapsed,
          timestamp
        };
      }

      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'LOW',
        detectionMethod: 'HTTPS_PROBE',
        reason: `Probe error: ${errMsg}`,
        responseTimeMs: elapsed,
        timestamp
      };
    }
  }

  /**
   * Internal bounded HTTPS client with strict redirects, domain validation, timeout, size limits, and false-positive defense
   */
  private performBoundedRequest(
    targetUrl: string,
    target: WebAccessTarget,
    redirectCount: number
  ): Promise<Omit<WebTargetResult, 'responseTimeMs' | 'timestamp'>> {
    return new Promise((resolve) => {
      if (redirectCount > this.maxRedirects) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Excessive redirects encountered during probe (${redirectCount} > ${this.maxRedirects})`
        });
      }

      let parsed: URL;
      try {
        parsed = new URL(targetUrl);
      } catch (err: any) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Malformed probe URL: ${err?.message}`
        });
      }

      // Enforce strict HTTPS requirement
      if (parsed.protocol !== 'https:') {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Insecure probe URL protocol '${parsed.protocol}' rejected. Only deterministic HTTPS probes are permitted.`
        });
      }

      // Validate that the request domain is allowed for this target service
      const allowedDomains = target.allowed_domains && target.allowed_domains.length > 0
        ? target.allowed_domains
        : [target.primary_domain];

      if (!isDomainAllowed(parsed.hostname, allowedDomains)) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Probe domain '${parsed.hostname}' does not match allowed domain set for ${target.service_name}`
        });
      }

      const client = https;
      let settled = false;

      const req = client.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: parsed.pathname + parsed.search,
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 FileSentinel-Probe/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
          },
          timeout: this.requestTimeoutMs
        },
        (res) => {
          const statusCode = res.statusCode || 0;
          const headers = res.headers;
          const location = headers.location;

          // 1. Handle Redirects (301, 302, 303, 307, 308)
          if ([301, 302, 303, 307, 308].includes(statusCode) && location) {
            let nextUrl: string;
            let nextParsed: URL;
            try {
              nextUrl = new URL(location, targetUrl).toString();
              nextParsed = new URL(nextUrl);
            } catch {
              nextUrl = location;
              nextParsed = parsed;
            }

            // Check for captive portal redirect (e.g. login.wifi, auth.gateway, captive)
            if (/captive|hotspot|portal|login\?|radius|auth\./i.test(nextUrl)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'BLOCKED',
                confidence: 'HIGH',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                reason: `Redirected to captive / network login portal: ${nextUrl}`
              });
            }

            // Check for corporate proxy block redirect (e.g., block.corporate.com, fortiguard, zscaler)
            if (/block|deny|firewall|fortinet|paloalto|zscaler|umbrella|barracuda/i.test(nextUrl)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'BLOCKED',
                confidence: 'HIGH',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                reason: `Redirected to corporate firewall block portal: ${nextUrl}`
              });
            }

            // Validate that redirect hostname stays within the approved domain set
            if (!isDomainAllowed(nextParsed.hostname, allowedDomains)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'INDETERMINATE',
                confidence: 'MEDIUM',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                reason: `Redirect target '${nextParsed.hostname}' left approved domain set for ${target.service_name}`
              });
            }

            // Valid target service redirect within approved domain set
            settled = true;
            return this.performBoundedRequest(nextUrl, target, redirectCount + 1).then(resolve);
          }

          // 2. Handle HTTP Status Blocks (403, 451)
          if (statusCode === 451) {
            settled = true;
            return resolve({
              category: target.category,
              service: target.service_name,
              target_domain: target.primary_domain,
              status: 'BLOCKED',
              confidence: 'HIGH',
              detectionMethod: 'HTTPS_PROBE',
              httpStatusCode: statusCode,
              reason: 'HTTP 451: Unavailable for Legal/Policy Reasons'
            });
          }

          // Collect bounded body snippet for verification (up to maxResponseSizeBytes)
          let bodyBuffer = '';
          res.setEncoding('utf8');

          res.on('data', (chunk) => {
            if (bodyBuffer.length < this.maxResponseSizeBytes) {
              bodyBuffer += chunk;
            } else {
              res.destroy(); // Terminate stream once size limit reached
            }
          });

          res.on('end', () => {
            if (settled) return;
            settled = true;

            const classification = this.classifyResponse(statusCode, headers, bodyBuffer, target);
            return resolve(classification);
          });
        }
      );

      req.setTimeout(this.requestTimeoutMs, () => {
        if (settled) return;
        settled = true;
        req.destroy();
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'UNREACHABLE',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          reason: 'Network request timed out'
        });
      });

      req.on('timeout', () => {
        if (settled) return;
        settled = true;
        req.destroy();
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'UNREACHABLE',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          reason: 'Network request timed out'
        });
      });

      req.on('close', () => {
        if (settled) return;
        settled = true;
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'UNREACHABLE',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          reason: 'Connection closed'
        });
      });

      req.on('error', (err: any) => {
        if (settled) return;
        settled = true;

        if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/i.test(err?.code || '')) {
          return resolve({
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'BLOCKED',
            confidence: 'HIGH',
            detectionMethod: 'HTTPS_PROBE',
            reason: `Connection refused / unresolvable: ${err?.message}`
          });
        }

        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          reason: `Network probe error: ${err?.message}`
        });
      });

      req.end();
    });
  }

  /**
   * Classify response body and headers with rigorous False-Positive and Block page recognition.
   * A response is ONLY ACCESSIBLE when deterministic evidence proves the response belongs to
   * the requested target service. Large body length alone NEVER makes a target ACCESSIBLE.
   */
  public classifyResponse(
    statusCode: number,
    headers: http.IncomingHttpHeaders,
    body: string,
    target: WebAccessTarget
  ): Omit<WebTargetResult, 'responseTimeMs' | 'timestamp'> {
    const lowerBody = body.toLowerCase();
    const serverHeader = String(headers['server'] || '').toLowerCase();

    // 1. Corporate Firewall / Proxy Block Signature Detection
    const blockPageSignatures = [
      'access denied',
      'access is denied',
      'url block',
      'website blocked',
      'category blocked',
      'policy violation',
      'content filter',
      'fortiguard',
      'palo alto networks',
      'zscaler',
      'cisco umbrella',
      'sonicwall',
      'sophos',
      'blue coat',
      'squid/proxy',
      'squid error',
      'the following error was encountered',
      'websense',
      'barracuda',
      'access to this web page is restricted',
      'blocked by administrator',
      'restricted by organization'
    ];

    const hasBlockSignature = blockPageSignatures.some(sig => lowerBody.includes(sig));

    if (hasBlockSignature) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        reason: 'Corporate firewall / security gateway block page signature matched'
      };
    }

    // 2. Explicit HTTP 403 Forbidden or 451 Unavailable For Legal/Policy Reasons
    if (statusCode === 403 || statusCode === 451) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        reason: statusCode === 451
          ? 'HTTP 451: Unavailable for Legal/Policy Reasons'
          : 'HTTP 403: Forbidden / Access Restricted'
      };
    }

    // 3. Captive Portal Detection in Body
    if (lowerBody.includes('captive portal') || lowerBody.includes('wifi authentication') || lowerBody.includes('hotspot login')) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        reason: 'Network intercepted by captive portal login screen'
      };
    }

    // 4. Temporary Service Outage or Server Error (HTTP 500..504)
    if (statusCode >= 500 && statusCode <= 504) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'LOW',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        reason: `Target server error HTTP ${statusCode} (possible temporary outage)`
      };
    }

    // 5. Successful Status (HTTP 200, 204, 302)
    if (statusCode >= 200 && statusCode < 400) {
      // Deterministic validation: must match expected target service signatures
      const matchesExpectedIdentifier = target.expected_identifiers.length > 0 && target.expected_identifiers.some(ident => {
        const cleanIdent = ident.toLowerCase().trim();
        return lowerBody.includes(cleanIdent) || serverHeader.includes(cleanIdent);
      });

      // CRITICAL: A response is ACCESSIBLE ONLY when deterministic evidence matches the target service.
      // Large generic body length (>500) MUST NOT trigger ACCESSIBLE.
      if (matchesExpectedIdentifier) {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'ACCESSIBLE',
          confidence: 'HIGH',
          detectionMethod: 'HTTPS_PROBE',
          httpStatusCode: statusCode,
          reason: `Target accessible with confirmed ${target.service_name} application signatures (HTTP ${statusCode})`
        };
      }

      // Generic response (no identifying signatures) -> INDETERMINATE (Never guess)
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'MEDIUM',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        reason: `Generic HTTP ${statusCode} response without confirmed ${target.service_name} signatures`
      };
    }

    return {
      category: target.category,
      service: target.service_name,
      target_domain: target.primary_domain,
      status: 'INDETERMINATE',
      confidence: 'LOW',
      detectionMethod: 'HTTPS_PROBE',
      httpStatusCode: statusCode,
      reason: `Unhandled HTTP response status: ${statusCode}`
    };
  }
}
