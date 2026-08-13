import { Rule } from '../types.js';

export const BUILTIN_RULES: Rule[] = [
  // SECRETS
  {
    id: 'SECRET-001',
    name: 'Possible Password',
    category: 'SECRETS',
    severity: 'CRITICAL',
    enabled: true,
    pattern: '(?i)(?:password|passwd|pwd|secret_key|api_secret)\\s*[:=]\\s*[\'"]?([^\'"\\s;,]{6,})[\'"]?',
    description: 'Possible hardcoded password or credential key detected in document content or code.',
    recommendation: 'Remove the credential immediately and rotate it if it is currently active in any system.',
    isBuiltIn: true
  },
  {
    id: 'SECRET-002',
    name: 'API Key',
    category: 'SECRETS',
    severity: 'CRITICAL',
    enabled: true,
    pattern: '(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\\s*[:=]\\s*[\'"]?([a-zA-Z0-9_\\-]{16,})[\'"]?|(?:AIzaSy|AKIA|ASIA|ghp_|glpat-|sk_live_|sk_test_)[a-zA-Z0-9_\\-]{16,}',
    description: 'High-entropy API key or service token signature detected.',
    recommendation: 'Invalidate key in provider portal, place key into secure secret store, and scrub document.',
    isBuiltIn: true
  },
  {
    id: 'SECRET-003',
    name: 'JWT Token',
    category: 'SECRETS',
    severity: 'HIGH',
    enabled: true,
    pattern: 'eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}',
    description: 'JSON Web Token (JWT) string detected.',
    recommendation: 'Ensure token contains no long-lived sensitive session data and revoke token if necessary.',
    isBuiltIn: true
  },
  {
    id: 'SECRET-004',
    name: 'Private Key',
    category: 'SECRETS',
    severity: 'CRITICAL',
    enabled: true,
    pattern: '-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE)? KEY-----',
    description: 'Cryptographic private key block (PEM header) detected in text.',
    recommendation: 'Remove private key immediately and regenerate certificates/keypairs.',
    isBuiltIn: true
  },

  // PII
  {
    id: 'PII-001',
    name: 'Email Address',
    category: 'PII',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    description: 'Personal or corporate email address detected.',
    recommendation: 'Mask or redact email addresses if document is intended for public or unauthorized audience.',
    isBuiltIn: true
  },
  {
    id: 'PII-002',
    name: 'Phone Number',
    category: 'PII',
    severity: 'LOW',
    enabled: true,
    pattern: '(?:\\+?\\d{1,3}[- .]?)?\\(?\\d{3}\\)?[- .]?\\d{3}[- .]?\\d{4}',
    description: 'Telephone number string identified.',
    recommendation: 'Review whether personal contact phone numbers are permitted in this document.',
    isBuiltIn: true
  },
  {
    id: 'PII-003',
    name: 'PAN-like Identifier',
    category: 'PII',
    severity: 'HIGH',
    enabled: true,
    pattern: '[A-Z]{5}[0-9]{4}[A-Z]{1}',
    description: 'Format matching Permanent Account Number (PAN) identifier pattern.',
    recommendation: 'Mask tax identifier numbers prior to external distribution.',
    isBuiltIn: true
  },
  {
    id: 'PII-004',
    name: 'Potential Aadhaar-like identifier',
    category: 'PII',
    severity: 'HIGH',
    enabled: true,
    pattern: '(?i)(?:(?:aadhaar|aadhar|uidai|uid|identity\\s*no|govt\\s*id|national\\s*id)[\\s\\S]{0,50}?\\b[2-9]\\d{3}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b|\\b[2-9]\\d{3}[\\s-]\\d{4}[\\s-]\\d{4}\\b)',
    description: 'Detects 12-digit Indian national identity Aadhaar numbers with structural formatting (spaces/hyphens) or explicit contextual keywords.',
    recommendation: 'Redact national identity digits to comply with privacy laws.',
    isBuiltIn: true
  },
  {
    id: 'PII-005',
    name: 'Bank Account Number',
    category: 'PII',
    severity: 'HIGH',
    enabled: true,
    pattern: '(?i)(?:account|acct|acc)[_\\s#]*[:=]?\\s*\\d{9,18}',
    description: 'Likely bank account number accompanied by contextual keywords.',
    recommendation: 'Confirm banking details are encrypted and rest heavily controlled.',
    isBuiltIn: true
  },
  {
    id: 'PII-006',
    name: 'IFSC Code',
    category: 'PII',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '[A-Z]{4}0[A-Z0-9]{6}',
    description: 'Bank branch IFSC financial routing code.',
    recommendation: 'Verify if branch routing data linked to accounts needs classification.',
    isBuiltIn: true
  },
  {
    id: 'PII-007',
    name: 'Credit / Debit Card Number',
    category: 'PII',
    severity: 'CRITICAL',
    enabled: true,
    pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b',
    description: 'Payment card number pattern matching Visa, MasterCard, Amex, or Discover.',
    recommendation: 'Remove full credit card details immediately to maintain PCI-DSS compliance.',
    isBuiltIn: true
  },

  // FINANCIAL
  {
    id: 'FIN-001',
    name: 'Salary / Payroll Information',
    category: 'FINANCIAL',
    severity: 'HIGH',
    enabled: true,
    pattern: '(?i)(?:salary|ctc|pay\\s*stub|monthly\\s*pay|compensation|bonus|gross\\s*pay)\\s*[:=]?\\s*\\$?(\\d{1,3}(?:,\\d{3})*|\\d+)',
    description: 'Compensation, payroll or salary details.',
    recommendation: 'Restrict document access strictly to HR and executive roles.',
    isBuiltIn: true
  },
  {
    id: 'FIN-002',
    name: 'Financial Transaction',
    category: 'FINANCIAL',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '(?i)(?:transaction\\s*id|txid|wire\\s*transfer|invoice\\s*#|payment\\s*ref)\\s*[:=]?\\s*([a-zA-Z0-9_-]{6,})',
    description: 'Payment invoice reference or wire transaction identifier.',
    recommendation: 'Store transactional logs in financial audit tools rather than open files.',
    isBuiltIn: true
  },

  // SECURITY
  {
    id: 'SEC-001',
    name: 'Internal IP Address',
    category: 'SECURITY',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b',
    description: 'RFC 1918 Private IPv4 address space instance detected.',
    recommendation: 'Ensure internal network topology details are masked before publishing.',
    isBuiltIn: true
  },
  {
    id: 'SEC-002',
    name: 'Database Connection String',
    category: 'SECURITY',
    severity: 'CRITICAL',
    enabled: true,
    pattern: '(?:mongodb(?:\\+srv)?|postgres|postgresql|mysql|mssql|oracle|sqlite|redis):\\/\\/[^\\s"\']+',
    description: 'Database connection URI string containing backend host or credentials.',
    recommendation: 'Move connection string to environment variables or key vault.',
    isBuiltIn: true
  },
  {
    id: 'SEC-003',
    name: 'SSH Config / Credentials',
    category: 'SECURITY',
    severity: 'HIGH',
    enabled: true,
    pattern: '(?i)(?:ssh-rsa|ssh-dss|ecdsa-sha2-nistp|ssh-ed25519)|(?i)Host\\s+[^*]+\\n\\s*HostName\\s+',
    description: 'SSH public key or SSH client configuration snippet.',
    recommendation: 'Verify SSH credentials are registered in key manager rather than local flat file.',
    isBuiltIn: true
  },

  // DOCUMENT STRUCTURE
  {
    id: 'DOC-001',
    name: 'Hidden Excel Worksheet',
    category: 'DOCUMENT',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '(?i)hidden_sheet|sheet_state_hidden',
    description: 'Workbook contains one or more hidden or very hidden worksheets.',
    recommendation: 'Inspect hidden worksheets to ensure sensitive data was not concealed unintentionally.',
    isBuiltIn: true
  },
  {
    id: 'DOC-002',
    name: 'External Workbook Link',
    category: 'DOCUMENT',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '(?i)external_link|external_relationship',
    description: 'Document references external network files or remote data sources.',
    recommendation: 'Audit external links to prevent data exfiltration via broken or untrusted references.',
    isBuiltIn: true
  },
  {
    id: 'DOC-003',
    name: 'Embedded Object',
    category: 'DOCUMENT',
    severity: 'MEDIUM',
    enabled: true,
    pattern: '(?i)embedded_object|ole_object',
    description: 'Embedded binary or executable object discovered within document.',
    recommendation: 'Review embedded payload or file attachment to confirm legitimacy.',
    isBuiltIn: true
  },
  {
    id: 'DOC-004',
    name: 'PDF JavaScript Feature',
    category: 'DOCUMENT',
    severity: 'HIGH',
    enabled: true,
    pattern: '(?i)\\/JavaScript|\\/JS|\\/Launch',
    description: 'Potentially risky document feature detected (PDF JavaScript action).',
    recommendation: 'Disable automatic script execution in PDF viewers and inspect script contents.',
    isBuiltIn: true
  },
  {
    id: 'DOC-005',
    name: 'External Relationship',
    category: 'DOCUMENT',
    severity: 'LOW',
    enabled: true,
    pattern: '(?i)external_relation|hyperlink_external',
    description: 'External hyperlink or resource reference present in document.',
    recommendation: 'Verify destination domain reputation for external links.',
    isBuiltIn: true
  }
];
