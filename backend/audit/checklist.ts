import { AuditParameter } from './models.js';

export const INITIAL_AUDIT_CHECKLIST: AuditParameter[] = [
  // --- CATEGORY 1: ZERO TOLERANCE (Score: 100, Fatal: YES) ---
  {
    id: 'ZTI-001',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Agency Identification: Board, GST Details',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['GST Registration Certificate', 'Agency Identification Board / Details', 'PAN / Incorporation Record'],
    keywords: ['GST', 'GSTIN', 'GST Registration', 'Goods and Services Tax', 'Registration Certificate', 'Agency Identification'],
    logic: 'SINGLE',
    evaluation_rules: ['Check for valid GSTIN or Agency Identification details'],
    enabled: true
  },
  {
    id: 'ZTI-002',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Agency Access Control',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Biometric access log', 'ID Card system configuration', 'Physical access control policy / photos'],
    keywords: ['biometric', 'access control', 'door access', 'badge reader', 'physical security', 'card system'],
    logic: 'SINGLE',
    distinguish_policy: true,
    evaluation_rules: ['Distinguish policy from physical/system implementation evidence'],
    enabled: true
  },
  {
    id: 'ZTI-003',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Dedicated workspace/systems for Phone Lending business',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Dedicated workspace documentation', 'System allocation sheet', 'Segregation proof'],
    keywords: ['phone lending', 'dedicated workspace', 'system allocation', 'segregated bay', 'lending desk'],
    logic: 'SINGLE',
    evaluation_rules: ['Verify segregated space/systems dedicated to lending operations'],
    enabled: true
  },
  {
    id: 'ZTI-004',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'DRA Passed / Trained Certificate',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['DRA Certificate', 'DRA Training Completion Certificate', 'Training Record'],
    keywords: ['DRA', 'Debt Recovery Agent', 'DRA Trained', 'DRA Certificate', 'NBFET', 'Training Certificate'],
    logic: 'SINGLE',
    requires_validity_check: true,
    expiry_required: true,
    evaluation_rules: ['Extract agent name, training status, cert number, issue date, expiry date'],
    enabled: true
  },
  {
    id: 'ZTI-005',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Valid Police Verification (PV) / Applied for',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Police Verification Report', 'Proof of Police Verification Application'],
    keywords: ['police verification', 'character certificate', 'PV report', 'police clearance', 'verification acknowledgement'],
    logic: 'OR',
    requires_validity_check: true,
    expiry_required: false,
    evaluation_rules: ['Distinguish VERIFIED, APPLIED, MISSING, EXPIRED, or UNCLEAR'],
    enabled: true
  },
  {
    id: 'ZTI-006',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Misconduct or another breach of COC',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Disciplinary Log', 'Code of Conduct Breach Report', 'Compliance Declaration'],
    keywords: ['misconduct', 'code of conduct breach', 'disciplinary action', 'compliance violation', 'incident log'],
    logic: 'SINGLE',
    requires_human_review: true,
    evaluation_rules: ['Requires HUMAN REVIEW. Absence of document alone does not guarantee compliance'],
    enabled: true
  },
  {
    id: 'ZTI-007',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Agent Onboarding Documents Authentication',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Agent Onboarding Checklist', 'KYC Authentication Record', 'Approval Form'],
    keywords: ['onboarding checklist', 'agent onboarding', 'KYC verification', 'background check', 'approval record'],
    logic: 'SINGLE',
    evaluation_rules: ['Check onboarding documentation and authenticated KYC records'],
    enabled: true
  },
  {
    id: 'ZTI-008',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Printer/Scanner restricted / USB & Cloud storage access restricted',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Endpoint Security Policy', 'DLP / GPO Configuration Export', 'IT Audit Screenshot'],
    keywords: ['USB restriction', 'cloud storage block', 'printer restricted', 'DLP policy', 'GPO configuration', 'removable media'],
    logic: 'AND',
    sub_controls: ['POLICY_EVIDENCE', 'IMPLEMENTATION_EVIDENCE'],
    requirements: [
      {
        id: 'POLICY_EVIDENCE',
        title: 'Endpoint Security Policy',
        evidence_types: ['ENDPOINT_SECURITY_POLICY', 'POLICY_DOCUMENT'],
        keywords: ['endpoint security policy', 'USB restriction policy', 'removable media policy', 'cloud storage policy', 'policy document']
      },
      {
        id: 'IMPLEMENTATION_EVIDENCE',
        title: 'Technical Implementation Configuration (GPO/DLP)',
        evidence_types: ['DLP_GPO_CONFIGURATION_EXPORT', 'REGISTRY_BLOCK_SCREENSHOT', 'TECHNICAL_CONFIG'],
        keywords: ['DLP configuration', 'GPO export', 'USB block registry', 'removable media disabled', 'cloud storage blocked', 'technical configuration']
      }
    ],
    distinguish_policy: true,
    evaluation_rules: ['Distinguish POLICY_EXISTS from IMPLEMENTATION_EVIDENCE. Both required for PASS.'],
    enabled: true
  },
  {
    id: 'ZTI-009',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Blacklisting of social sites/personal email ID/messaging apps',
    fatal: true,
    severity: 'CRITICAL',
    required_evidence: ['Web Filtering Policy', 'Firewall / Proxy Configuration Export', 'Endpoint Policy'],
    keywords: ['web filtering', 'blacklisting', 'social media block', 'personal email block', 'messaging apps restricted', 'proxy block'],
    logic: 'AND',
    sub_controls: ['POLICY_EVIDENCE', 'IMPLEMENTATION_EVIDENCE'],
    requirements: [
      {
        id: 'POLICY_EVIDENCE',
        title: 'Web Filtering / Acceptable Use Policy',
        evidence_types: ['WEB_FILTERING_POLICY', 'POLICY_DOCUMENT'],
        keywords: ['web filtering policy', 'acceptable use policy', 'social media policy', 'policy document']
      },
      {
        id: 'IMPLEMENTATION_EVIDENCE',
        title: 'Technical Filtering / Proxy Configuration',
        evidence_types: ['FIREWALL_PROXY_CONFIGURATION_EXPORT', 'URL_FILTERING_RULE_EXPORT', 'TECHNICAL_CONFIG'],
        keywords: ['firewall block rule', 'proxy blacklisting', 'URL filtering config', 'social sites blocked', 'web proxy rule', 'technical configuration']
      }
    ],
    distinguish_policy: true,
    evaluation_rules: ['Distinguish policy document from technical implementation evidence. Both required for PASS.'],
    enabled: true
  },
  {
    id: 'ZTI-010',
    category: 'ZERO_TOLERANCE',
    category_name: 'Regulatory and Operational Integrity',
    category_weight: 100,
    parameter: 'Clean desk policy',
    fatal: true,
    severity: 'HIGH',
    required_evidence: ['Clean Desk Policy', 'Inspection Records', 'Audit Photos / Compliance Declarations'],
    keywords: ['clean desk', 'clean desk policy', 'workspace inspection', 'nightly audit', 'compliance declaration'],
    logic: 'SINGLE',
    distinguish_policy: true,
    requires_human_review: true,
    evaluation_rules: ['Do not conclude physical workspace compliance from policy alone'],
    enabled: true
  },

  // --- CATEGORY 2: GOVERNANCE, COMPLIANCE & INFOSEC (Score: 60, Fatal: NO) ---
  {
    id: 'GCI-001',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Valid agency ID Card and Endorsement Card (for Field)',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Agency ID Card Sample/Register', 'Field Endorsement Card'],
    keywords: ['agency ID card', 'endorsement card', 'field agent ID', 'identification card', 'badge issue'],
    logic: 'SINGLE',
    requires_validity_check: true,
    expiry_required: false,
    evaluation_rules: ['Verify validity and availability of ID and Field Endorsement cards'],
    enabled: true
  },
  {
    id: 'GCI-002',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'ID Deactivation & Agent Termination process',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Termination Policy', 'Deactivation Procedure', 'Agent Deactivation Log'],
    keywords: ['termination process', 'ID deactivation', 'offboarding checklist', 'deactivation log', 'exit process'],
    logic: 'SINGLE',
    distinguish_policy: true,
    evaluation_rules: ['Verify deactivation process and actual termination sample records'],
    enabled: true
  },
  {
    id: 'GCI-003',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Agency Staff in appropriate attire',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Dress Code Policy', 'Inspection Reports', 'Workspace Photos'],
    keywords: ['dress code', 'attire policy', 'formal wear', 'inspection report', 'attire review'],
    logic: 'SINGLE',
    requires_human_review: true,
    evaluation_rules: ['Requires HUMAN REVIEW if physical evidence is ambiguous'],
    enabled: true
  },
  {
    id: 'GCI-004',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Refresher trainings conducted; mandatory attendance sheet',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Refresher Training Module', 'Attendance Sheet', 'Training Records'],
    keywords: ['refresher training', 'attendance sheet', 'mandatory training', 'training log', 'participant list'],
    logic: 'SINGLE',
    evaluation_rules: ['Extract training name, date, participants, attendance, trainer, completion status'],
    enabled: true
  },
  {
    id: 'GCI-005',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Agency Performance and Evaluation',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Target vs Actual Report', 'Performance Memos', 'No Dues Certificate (NDC)', 'Asset Management Declaration'],
    keywords: ['target vs actual', 'performance report', 'NDC', 'no dues certificate', 'asset management declaration', 'agency evaluation'],
    logic: 'SINGLE',
    evaluation_rules: ['Check performance evaluation records and NDC declarations'],
    enabled: true
  },
  {
    id: 'GCI-006',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Snipping Tool & MS Paint disabled',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Endpoint Security Configuration', 'GPO AppLocker / Software Restriction Policy', 'Device Audit Log'],
    keywords: ['snipping tool disabled', 'ms paint disabled', 'screen capture restricted', 'AppLocker policy', 'software restriction policy'],
    logic: 'SINGLE',
    distinguish_policy: true,
    evaluation_rules: ['Technical audit configuration required. Policy document alone must NOT pass'],
    enabled: true
  },
  {
    id: 'GCI-007',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Password policy of agencies being followed',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Password Policy Document', 'Active Directory Password Policy Export', 'IAM Compliance Report'],
    keywords: ['password policy', 'complexity requirements', 'password expiration', 'Active Directory GPO', 'IAM policy'],
    logic: 'SINGLE',
    distinguish_policy: true,
    evaluation_rules: ['Verify policy document and Active Directory / GPO configuration proof'],
    enabled: true
  },
  {
    id: 'GCI-008',
    category: 'GOVERNANCE_COMPLIANCE_INFOSEC',
    category_name: 'Governance, Compliance & INFOSEC',
    category_weight: 60,
    parameter: 'Updated Windows OS',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Patch Compliance Report', 'Endpoint Inventory Export', 'Windows Version / Build Log'],
    keywords: ['windows update', 'patch compliance', 'OS version', 'build number', 'WSUS report', 'endpoint inventory'],
    logic: 'SINGLE',
    evaluation_rules: ['Analyze endpoint OS versions/builds against current patch baseline'],
    enabled: true
  },

  // --- CATEGORY 3: INFRASTRUCTURE & PROCESS MANAGEMENT (Score: 40, Fatal: NO) ---
  {
    id: 'IPM-001',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'PF & ESIC Registration Certificate OR Principal Employer Registration Certificate',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['PF Registration Certificate', 'ESIC Registration Certificate', 'Principal Employer Registration Certificate'],
    keywords: ['PF registration', 'provident fund', 'ESIC certificate', 'principal employer', 'EPFO registration'],
    logic: 'OR',
    sub_controls: ['PF_ESIC_REGISTRATION', 'PRINCIPAL_EMPLOYER_CERTIFICATE'],
    requirements: [
      {
        id: 'PF_ESIC_REGISTRATION',
        title: 'PF & ESIC Registration Certificate',
        evidence_types: ['PF_ESIC_CERTIFICATE', 'PF_REGISTRATION', 'ESIC_REGISTRATION'],
        keywords: ['PF registration', 'provident fund', 'ESIC certificate', 'EPFO registration', 'ESIC code', 'establishment code', 'PF', 'ESIC', 'EPFO']
      },
      {
        id: 'PRINCIPAL_EMPLOYER_CERTIFICATE',
        title: 'Principal Employer Registration Certificate (Form I/II)',
        evidence_types: ['PRINCIPAL_EMPLOYER_CERTIFICATE', 'CLRA_REGISTRATION'],
        keywords: ['principal employer', 'contract labour', 'form i', 'form ii', 'clra registration', 'certificate of registration of principal employer']
      }
    ],
    evaluation_rules: ['PASS if valid evidence for PF & ESIC OR Principal Employer Certificate exists'],
    enabled: true
  },
  {
    id: 'IPM-002',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'HR & Anti-Sexual Harassment Policy',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['HR Policy', 'POSH Policy Document', 'Employee Handbook'],
    keywords: ['HR policy', 'POSH policy', 'sexual harassment', 'employee handbook', 'ICC committee'],
    logic: 'SINGLE',
    evaluation_rules: ['Verify policy existence, version, effective date, and approval status'],
    enabled: true
  },
  {
    id: 'IPM-003',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Rent or Lease Agreement for agency premises & Shops and Establishment Certificate',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Rent / Lease Agreement', 'Shops and Establishment Certificate'],
    keywords: ['rent agreement', 'lease agreement', 'shops and establishment', 'premises agreement', 'commercial lease'],
    logic: 'AND',
    sub_controls: ['RENT_LEASE_AGREEMENT', 'SHOPS_ESTABLISHMENT_CERTIFICATE'],
    requirements: [
      {
        id: 'RENT_LEASE_AGREEMENT',
        title: 'Rent or Lease Agreement for agency premises',
        evidence_types: ['LEASE_AGREEMENT', 'RENT_AGREEMENT'],
        keywords: ['rent agreement', 'lease agreement', 'premises agreement', 'commercial lease', 'lessor', 'lessee', 'landlord', 'tenant']
      },
      {
        id: 'SHOPS_ESTABLISHMENT_CERTIFICATE',
        title: 'Shops and Establishment Act Registration Certificate',
        evidence_types: ['SHOPS_ESTABLISHMENT_CERTIFICATE', 'SHOPS_ACT_REGISTRATION'],
        keywords: ['shops and establishment', 'shops & establishment', 'form c', 'shops act', 'commercial establishment', 'registration certificate']
      }
    ],
    evaluation_rules: ['Only PASS when BOTH Rent/Lease Agreement AND Shops & Establishment Certificate exist'],
    enabled: true
  },
  {
    id: 'IPM-004',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Commercial General Liability Insurance (Telecalling Agency)',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['Commercial General Liability Insurance Policy'],
    keywords: ['commercial general liability', 'CGL policy', 'insurance policy', 'liability coverage', 'indemnity insurance'],
    logic: 'SINGLE',
    requires_validity_check: true,
    expiry_required: true,
    evaluation_rules: ['Extract policy number, insured org, coverage amount, start date, expiry date, insurer. Check validity vs audit date'],
    enabled: true
  },
  {
    id: 'IPM-005',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Visitor register maintained by the agency',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Visitor Register Log', 'Visitor Entry Register CSV/PDF/Scan'],
    keywords: ['visitor register', 'visitor log', 'guest register', 'visitor entry', 'access log book'],
    logic: 'SINGLE',
    evaluation_rules: ['Verify register records exist for the active audit period'],
    enabled: true
  },
  {
    id: 'IPM-006',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'CCTV installed with recordings retained for minimum 90 days',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['CCTV System Configuration', 'Retention Log / Storage Settings Export', 'CCTV Audit Photos'],
    keywords: ['CCTV', 'surveillance camera', 'recording retention', '90 days retention', 'DVR config', 'NVR retention'],
    logic: 'AND',
    sub_controls: ['CCTV_INSTALLED', 'CCTV_RETENTION_90_DAYS'],
    requirements: [
      {
        id: 'CCTV_INSTALLED',
        title: 'CCTV Camera Installation & Inventory',
        evidence_types: ['CCTV_INSTALLATION_RECORD', 'CAMERA_INVENTORY', 'CCTV_SYSTEM_CONFIG', 'CCTV_RETENTION_CONFIGURATION'],
        keywords: ['cctv installation', 'camera inventory', 'surveillance camera', 'camera layout', 'installed cameras', 'dvr installation', 'cctv installed', 'cctv system', 'cameras', 'inventory']
      },
      {
        id: 'CCTV_RETENTION_90_DAYS',
        title: 'CCTV Recording Retention Configuration (Minimum 90 Days)',
        evidence_types: ['CCTV_RETENTION_CONFIGURATION', 'STORAGE_RETENTION_LOG', 'CCTV_SYSTEM_CONFIG'],
        keywords: ['90 days retention', 'recording retention', 'retention period', 'dvr config', 'nvr retention', 'storage retention', 'days retention', '90 days', 'retention settings']
      }
    ],
    distinguish_policy: true,
    evaluation_rules: ['Compound check: CCTV installed AND storage retention >= 90 days. Policy document alone cannot pass.'],
    enabled: true
  },
  {
    id: 'IPM-007',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Fire Extinguisher available, functional, and not expired',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Fire Extinguisher Inspection Certificate', 'Maintenance Log', 'Inspection Tag Photos'],
    keywords: ['fire extinguisher', 'extinguisher inspection', 'refill date', 'fire safety tag', 'pressure gauge status'],
    logic: 'GROUP',
    sub_controls: ['AVAILABLE', 'FUNCTIONAL', 'NOT_EXPIRED'],
    requirements: [
      {
        id: 'AVAILABLE',
        title: 'Fire Extinguisher Available on Premises',
        evidence_types: ['FIRE_EXTINGUISHER_INSPECTION', 'FIRE_SAFETY_EQUIPMENT'],
        keywords: ['fire extinguisher', 'extinguisher tag', 'equipment location', 'cylinder']
      },
      {
        id: 'FUNCTIONAL',
        title: 'Fire Extinguisher Functional & Inspected',
        evidence_types: ['FIRE_EXTINGUISHER_INSPECTION', 'FIRE_SAFETY_EQUIPMENT'],
        keywords: ['pressure gauge', 'functional', 'cylinder inspection', 'serviceability', 'gauge green', 'pressure ok']
      },
      {
        id: 'NOT_EXPIRED',
        title: 'Fire Extinguisher Refill Not Expired',
        evidence_types: ['FIRE_EXTINGUISHER_INSPECTION', 'FIRE_SAFETY_EQUIPMENT'],
        keywords: ['refill date', 'due date', 'not expired', 'validity', 'next inspection'],
        requires_validity_check: true,
        expiry_required: true
      }
    ],
    requires_validity_check: true,
    expiry_required: true,
    evaluation_rules: ['Verify availability, functional status, and unexpired refill date'],
    enabled: true
  },
  {
    id: 'IPM-008',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Fire Drill conducted by the agency (latest one year)',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Fire Drill Report', 'Fire Drill Attendance Record'],
    keywords: ['fire drill', 'evacuation drill', 'mock drill', 'fire drill report', 'fire safety drill'],
    logic: 'SINGLE',
    requires_validity_check: true,
    expiry_required: false,
    validity_type: 'RECENCY',
    max_age_days: 365,
    evaluation_rules: ['Extract drill date and compare against audit date. FAIL if drill date > 1 year before audit date'],
    enabled: true
  },
  {
    id: 'IPM-009',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Power Backup / Internet Backup / Antivirus on systems',
    fatal: false,
    severity: 'HIGH',
    required_evidence: ['UPS / Generator Maintenance Log', 'Secondary ISP Lease / Config', 'Antivirus Console Report'],
    keywords: ['power backup', 'UPS', 'generator', 'secondary ISP', 'internet backup', 'antivirus', 'endpoint protection', 'EDR'],
    logic: 'GROUP',
    sub_controls: ['POWER_BACKUP', 'INTERNET_BACKUP', 'ANTIVIRUS'],
    requirements: [
      {
        id: 'POWER_BACKUP',
        title: 'Operational Power Backup (UPS / Generator / Inverter)',
        evidence_types: ['POWER_BACKUP_LOG', 'UPS_MAINTENANCE', 'GENERATOR_LOG'],
        keywords: ['power backup', 'UPS', 'generator', 'dg set', 'battery bank', 'load test', 'inverter backup']
      },
      {
        id: 'INTERNET_BACKUP',
        title: 'Secondary Redundant Internet Link / ISP Failover',
        evidence_types: ['INTERNET_BACKUP_CONFIG', 'SECONDARY_ISP_LEASE', 'DUAL_WAN_CONFIG'],
        keywords: ['internet backup', 'secondary ISP', 'dual-WAN', 'failover link', 'redundant internet', 'secondary leased line', 'backup broadband']
      },
      {
        id: 'ANTIVIRUS',
        title: 'Antivirus / Endpoint Protection (EDR) with Up-to-date Definitions',
        evidence_types: ['ANTIVIRUS_CONSOLE_REPORT', 'ENDPOINT_PROTECTION_EXPORT', 'EDR_STATUS'],
        keywords: ['antivirus', 'endpoint protection', 'EDR', 'crowdstrike', 'windows defender', 'virus definitions', 'definitions up to date', 'antivirus console']
      }
    ],
    evaluation_rules: ['Evaluate three sub-controls individually and return individual evidence status'],
    enabled: true
  },
  {
    id: 'IPM-010',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Business Continuity Plan of the agency',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Business Continuity Plan (BCP) Document', 'Disaster Recovery Plan'],
    keywords: ['business continuity plan', 'BCP', 'disaster recovery', 'DR plan', 'continuity procedure'],
    logic: 'SINGLE',
    evaluation_rules: ['Verify BCP policy existence, approval status, version, and review date'],
    enabled: true
  },
  {
    id: 'IPM-011',
    category: 'INFRASTRUCTURE_PROCESS_MANAGEMENT',
    category_name: 'Infrastructure & Process Management',
    category_weight: 40,
    parameter: 'Escalation Matrix available with Collection agency',
    fatal: false,
    severity: 'MEDIUM',
    required_evidence: ['Escalation Matrix Document', 'Contact Hierarchy Chart'],
    keywords: ['escalation matrix', 'escalation hierarchy', 'contact matrix', 'grievance escalation', 'support contact list'],
    logic: 'SINGLE',
    evaluation_rules: ['Verify presence of structured escalation contact roles and levels'],
    enabled: true
  }
];
