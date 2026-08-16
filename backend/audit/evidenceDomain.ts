import { EvidenceDomain, EvidenceSourceType } from './models.js';

export interface SourceClassificationResult {
  sourceType: EvidenceSourceType;
  reason: string;
  isAuditEvidenceCandidate: boolean;
}

export interface DocumentDomainResult {
  primaryDomain: EvidenceDomain;
  secondaryDomains: EvidenceDomain[];
  confidence: number;
  detectedIdentifiers: string[];
  isPolicy: boolean;
  isImplementation: boolean;
  explanation: string;
}

/**
 * Classifies file source to exclude test fixtures, manifests, test suites, and app metadata.
 * Only files of type 'DOCUMENT_EVIDENCE' are eligible to serve as audit compliance evidence.
 */
export function classifyEvidenceSource(
  filename: string,
  filePath: string = '',
  text: string = ''
): SourceClassificationResult {
  const fnLower = (filename || '').toLowerCase().trim();
  const fpLower = (filePath || '').toLowerCase().replace(/\\/g, '/');
  const textSample = (text || '').substring(0, 4000).toLowerCase();

  // 1. Check for TEST METADATA by filename or path
  const testManifestPatterns = [
    /^manifest\.(csv|json|xml|txt)$/i,
    /dataset[-_]manifest/i,
    /expected[-_]results/i,
    /test[-_]manifest/i,
    /test[-_]fixture/i,
    /test[-_]instruction/i,
    /test[-_]report/i,
    /test[-_]plan/i,
    /test[-_]suite/i,
    /audit[-_]test/i,
    /test[-_]summary/i,
    /^readme(\.(md|txt|markdown))?$/i,
    /^instructions(\.(md|txt|markdown))?$/i,
  ];

  for (const pattern of testManifestPatterns) {
    if (pattern.test(fnLower)) {
      return {
        sourceType: 'TEST_METADATA',
        reason: `File '${filename}' is test metadata/manifest and is excluded from compliance evidence.`,
        isAuditEvidenceCandidate: false
      };
    }
  }

  // 2. Check for SYSTEM / APP METADATA
  const systemAppMetadataFiles = [
    'package.json',
    'package-lock.json',
    'tsconfig.json',
    'tsconfig.node.json',
    'vite.config.ts',
    'metadata.json',
    'components.json',
    '.env',
    '.env.example',
    '.gitignore',
    'thumbs.db',
    '.ds_store'
  ];

  if (systemAppMetadataFiles.includes(fnLower)) {
    return {
      sourceType: 'APPLICATION_METADATA',
      reason: `File '${filename}' is application build configuration and is excluded from compliance evidence.`,
      isAuditEvidenceCandidate: false
    };
  }

  // File extension checks for system artifacts
  if (/\.(sqlite|sqlite-journal|db|db-journal|log|tmp|bak|map)$/i.test(fnLower)) {
    return {
      sourceType: 'SYSTEM_METADATA',
      reason: `System artifact '${filename}' is excluded from compliance evidence.`,
      isAuditEvidenceCandidate: false
    };
  }

  // Path checks: files located in tests/ directory that are test specifications or fixtures
  // (unless it's in the golden-audit/documents directory specifically used as synthetic audit inputs)
  if (
    (fpLower.includes('/tests/') || fpLower.includes('/__tests__/')) &&
    !fpLower.includes('/golden-audit/documents/') &&
    !fpLower.includes('/sample-files/')
  ) {
    if (/\.(ts|js|jsx|tsx|sh)$/i.test(fnLower) || testManifestPatterns.some(p => p.test(fnLower))) {
      return {
        sourceType: 'TEST_METADATA',
        reason: `File in test suite directory '${filePath}' is excluded from compliance evidence.`,
        isAuditEvidenceCandidate: false
      };
    }
  }

  // 3. Content-based Test Metadata Detection
  // Detect test runner artifacts, dataset manifests, test fixture schemas
  const testContentSignatures = [
    '"format_counts"',
    'format_counts:',
    '"expected_validation"',
    'expected_validation:',
    'synthetic multi-format audit documents',
    'deterministic validation dataset containing real synthetic documents',
    'expected outcome:',
    'expected status:',
    'expected_outcome',
    '# test instructions for file-sentinel'
  ];

  for (const sig of testContentSignatures) {
    if (textSample.includes(sig)) {
      return {
        sourceType: 'TEST_METADATA',
        reason: `Document content matches test fixture/manifest structure and is excluded from compliance evidence.`,
        isAuditEvidenceCandidate: false
      };
    }
  }

  return {
    sourceType: 'DOCUMENT_EVIDENCE',
    reason: `Document '${filename}' is eligible documentary evidence for compliance audit.`,
    isAuditEvidenceCandidate: true
  };
}

/**
 * Deterministically classifies a document into its primary compliance domain
 * using strict regexes, structural identifiers, and domain contextual rules.
 */
export function classifyDocumentDomain(
  filename: string,
  text: string,
  extractedFields: Record<string, any> = {}
): DocumentDomainResult {
  const fnLower = (filename || '').toLowerCase();
  const textSample = (text || '').substring(0, 15000);
  const textLower = textSample.toLowerCase();

  const detectedIdentifiers: string[] = [];
  const secondaryDomains: EvidenceDomain[] = [];
  let isPolicy = false;
  let isImplementation = false;

  // Policy vs Implementation Detection
  if (
    /(?:policy\b|standard\s*operating\s*procedure|\bsop\b|guidelines|terms of reference|governance document|policy statement|policy reference)/i.test(textSample) ||
    fnLower.includes('policy') ||
    fnLower.includes('sop')
  ) {
    isPolicy = true;
  }

  if (
    /(?:configuration\s*export|registry_key|audit\s*dump|console\s*export|system log|table\s*export|csv\s*export|active directory gpo export|gpo_guid|hklm\\)/i.test(textSample) ||
    fnLower.includes('export') ||
    fnLower.includes('log') ||
    fnLower.includes('dump') ||
    fnLower.includes('report')
  ) {
    isImplementation = true;
  }

  // -------------------------------------------------------------
  // DOMAIN 1: GST_REGISTRATION
  // -------------------------------------------------------------
  const gstinMatch = textSample.match(/\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z0-9]{1}Z[A-Z0-9]{1}\b/);
  const hasGstForm = /(?:form\s*gst\s*reg[-_]?06|goods and services tax|registration certificate under goods and services tax act|central goods and services tax)/i.test(textSample);
  if (gstinMatch || (hasGstForm && /(?:gstin|legal name|trade name|taxpayer)/i.test(textSample))) {
    if (gstinMatch) detectedIdentifiers.push(`GSTIN:${gstinMatch[0]}`);
    return {
      primaryDomain: 'GST_REGISTRATION',
      secondaryDomains,
      confidence: gstinMatch ? 0.98 : 0.90,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'GST Registration Certificate identified with official GSTIN / tax authority credentials.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 2: COMMERCIAL_GENERAL_LIABILITY_INSURANCE
  // -------------------------------------------------------------
  const insPolicyMatch = textSample.match(/\b(POL|INS|CGL|PL)[-_#:\s]\d{3,15}\b/i) || textSample.match(/\b(?:policy\s*(?:no|number|#|num|id)[:\s#.]+|policy[:#]\s*)([A-Z0-9\-_/]{4,25})\b/i);
  const hasInsuranceContext = /(?:commercial general liability|cgl policy|liability insurance|indemnity insurance|sum insured|limit of indemnity|premium paid|insurance company)/i.test(textSample);
  if (hasInsuranceContext && (insPolicyMatch || /(?:insurer|insured|coverage limit|period of insurance)/i.test(textSample))) {
    if (insPolicyMatch) detectedIdentifiers.push(`POLICY_NO:${insPolicyMatch[1] || insPolicyMatch[0]}`);
    return {
      primaryDomain: 'COMMERCIAL_GENERAL_LIABILITY_INSURANCE',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Commercial General Liability Insurance policy document identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 3: DRA_CERTIFICATION
  // -------------------------------------------------------------
  const draMatch = textSample.match(/\b(DRA|NBFET|IIBF)[-_#:\s/]?\d{3,15}\b/i) ||
    textSample.match(/\b(?:cert(?:ificate)?\s*(?:no|number|#)[:\s#.]*)([A-Z0-9\-_/]{4,25})\b/i) ||
    textSample.match(/\b(?:dra\s*\/\s*\d{4}\s*\/\s*\d{3,10})\b/i);
  const hasDraContext = /(?:debt recovery agent|dra\s*cert|iibf|nbfet|recovery agent training|candidate name|has passed the examination for debt recovery agents|dra passed|dra trained|dra certification|trained certificate)/i.test(textSample) ||
    (fnLower.includes('dra') && /(?:certificate|training|passed|exam|roll|agent)/i.test(textSample));
  if (hasDraContext && (draMatch || /(?:candidate name|roll number|marks obtained|qualified|passed|training status)/i.test(textSample))) {
    if (draMatch) detectedIdentifiers.push(`DRA_CERT:${draMatch[1] || draMatch[0]}`);
    return {
      primaryDomain: 'DRA_CERTIFICATION',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Debt Recovery Agent (DRA) certificate identified with candidate accreditation details.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 4: POLICE_VERIFICATION
  // -------------------------------------------------------------
  const pvAckMatch = textSample.match(/\b(PV-ACK|ACK|PCC)[-_#:\s]?\d{3,15}\b/i) || textSample.match(/\b(?:acknowledgement\s*(?:no|number|#|slip|id)?[:#]\s*|ack\s*(?:no|number|#)[:\s#.]*)([A-Z0-9\-_/]{3,25})\b/i);
  const hasPoliceContext = /(?:police verification|police clearance certificate|pcc|character & background verification|antecedent verification|state police|district police)/i.test(textSample);
  if (hasPoliceContext && (pvAckMatch || /(?:verified|applied|clearance status|no criminal record|applicant name)/i.test(textSample))) {
    if (pvAckMatch) detectedIdentifiers.push(`PV_ACK:${pvAckMatch[1] || pvAckMatch[0]}`);
    return {
      primaryDomain: 'POLICE_VERIFICATION',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Police Verification Report or Application Acknowledgement document identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 5: CCTV SURVEILLANCE & RETENTION
  // -------------------------------------------------------------
  const hasCctvHardware = /(?:cctv\b|surveillance camera|dvr\b|nvr\b|bullet camera|dome camera|camera inventory|camera channel|cam 01|channel 1)/i.test(textSample);
  const hasCctvRetention = /(?:retention|recording duration|90 days|dvr config|nvr config|storage settings|overwrite after|tb storage)/i.test(textSample);
  if (hasCctvHardware || (fnLower.includes('cctv') && !fnLower.includes('access_control'))) {
    if (hasCctvRetention) {
      detectedIdentifiers.push('CCTV_RETENTION_CONFIG');
      return {
        primaryDomain: 'CCTV_SURVEILLANCE_RETENTION',
        secondaryDomains: ['CCTV_RETENTION_CONFIG', 'CCTV_INSTALLATION'],
        confidence: 0.95,
        detectedIdentifiers,
        isPolicy,
        isImplementation: true,
        explanation: 'CCTV surveillance configuration / retention schedule identified.'
      };
    }
    return {
      primaryDomain: 'CCTV_SURVEILLANCE_RETENTION',
      secondaryDomains: ['CCTV_INSTALLATION'],
      confidence: 0.92,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'CCTV surveillance hardware installation / inventory document identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 6: BIOMETRIC / ACCESS CONTROL
  // -------------------------------------------------------------
  const hasBiometricLogs = /(?:biometric\s*terminal|biometric\s*log|door\s*controller|access\s*controller|badge\s*reader|swipe\s*card|rfid\s*reader|punch\s*in|punch\s*out|door\s*access\s*log|turnstile)/i.test(textSample);
  if (hasBiometricLogs || (fnLower.includes('biometric') || (fnLower.includes('access_control') && !fnLower.includes('cctv')))) {
    return {
      primaryDomain: 'BIOMETRIC_ACCESS_CONTROL',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy,
      isImplementation: true,
      explanation: 'Biometric / Door Access Control hardware and terminal log records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 7: ENDPOINT DATA RESTRICTION (USB, Cloud, Storage GPO/DLP)
  // -------------------------------------------------------------
  const hasUsbCloudKeywords = /(?:removable\s*media|usb[-_\s]*storage|usb[-_\s]*port|cloud[-_\s]*storage|storage\s*device\s*policies|writeprotect|applocker|device[-_\s]*control|printer[-_\s]*restriction|scanner[-_\s]*restriction|usb[-_\s]*restriction|usb[-_\s]*control|storage[-_\s]*control)/i.test(textSample) ||
    fnLower.includes('usb') ||
    fnLower.includes('dlp');
  const hasUsbTechnicalDump = /(?:storagedevicepolicies|deny_all|removablestoragedevices|block[-_\s]*usb|usb[-_\s]*(?:storage[-_\s]*)?block(?:ed)?|dlp[-_\s]*agent|endpoint[-_\s]*dlp|gpo_endpoint_security|usb[-_\s]*blocking|active[-_\s]*gpo|gpo[-_\s]*name|registry_key|hklm\\|storport|usbstor|gpo_guid|gpo_status|last_applied|syn-endpoint)/i.test(textSample);
  if (hasUsbTechnicalDump || (hasUsbCloudKeywords && (fnLower.includes('usb') || fnLower.includes('gpo') || fnLower.includes('dlp') || fnLower.includes('device_control')))) {
    const isExplicitPolicy = (fnLower.includes('policy') && !fnLower.includes('implementation') && !fnLower.includes('export') && !fnLower.includes('.csv')) ||
      /(?:information security policy|endpoint security policy|policy statement|policy reference|sop\b|usb storage control policy)/i.test(textSample);
    const hasTechnicalDump = /(?:registry_key|hklm\\|configured_value|storport=\d|usbstor|gpo_guid|active direct(?:ory)? gpo export|gpo_status|last_applied|syn-endpoint)/i.test(textSample) ||
      fnLower.includes('export') ||
      fnLower.includes('dump') ||
      fnLower.includes('implementation') ||
      (fnLower.includes('.csv') && !fnLower.includes('manifest'));

    if (isExplicitPolicy && !hasTechnicalDump) {
      return {
        primaryDomain: 'ENDPOINT_SECURITY_POLICY',
        secondaryDomains: ['ENDPOINT_DATA_RESTRICTION'],
        confidence: 0.95,
        detectedIdentifiers,
        isPolicy: true,
        isImplementation: false,
        explanation: 'Endpoint security & removable storage restriction policy document identified.'
      };
    }
    return {
      primaryDomain: 'ENDPOINT_DATA_RESTRICTION_CONFIG',
      secondaryDomains: ['ENDPOINT_DATA_RESTRICTION'],
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: isExplicitPolicy && !hasTechnicalDump,
      isImplementation: true,
      explanation: 'Technical GPO / DLP endpoint data restriction configuration export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 8: WEB & COMMUNICATION FILTERING (Proxy, Firewall, URL Blacklist)
  // -------------------------------------------------------------
  const hasWebFilteringKeywords = /(?:web\s*filtering|url\s*filtering|social\s*media\s*block|personal\s*email\s*block|messaging\s*apps?\s*block|proxy\s*server|firewall\s*blacklist|url\s*category)/i.test(textSample);
  const hasFirewallRules = /(?:facebook\.com|whatsapp|telegram|instagram|gmail\.com|action:\s*deny|action:\s*drop|filter\s*rule|proxy_rule|squid|fortinet|palo\s*alto|checkpoint)/i.test(textSample);
  if (hasWebFilteringKeywords || (hasFirewallRules && (fnLower.includes('firewall') || fnLower.includes('proxy') || fnLower.includes('web') || fnLower.includes('blacklist')))) {
    const isExplicitWebPolicy = fnLower.includes('policy') || /(?:acceptable use policy|internet usage policy|web filtering policy|policy statement)/i.test(textSample);
    const hasTechnicalFirewallDump = /(?:action:\s*(?:deny|drop)|rule_id|proxy_rule|squid proxy|fortigate|iptables|blacklist_rules_export|\.csv)/i.test(textSample) || fnLower.includes('export') || fnLower.includes('dump') || fnLower.includes('rules');
    if (isExplicitWebPolicy && !hasTechnicalFirewallDump) {
      return {
        primaryDomain: 'WEB_FILTERING_POLICY',
        secondaryDomains: ['WEB_COMMUNICATION_FILTERING'],
        confidence: 0.90,
        detectedIdentifiers,
        isPolicy: true,
        isImplementation: false,
        explanation: 'Web and communication filtering acceptable use policy document identified.'
      };
    }
    return {
      primaryDomain: 'WEB_COMMUNICATION_FILTERING_CONFIG',
      secondaryDomains: ['WEB_COMMUNICATION_FILTERING'],
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: isExplicitWebPolicy && !hasTechnicalFirewallDump,
      isImplementation: true,
      explanation: 'Firewall / Proxy URL blacklisting configuration rule export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 9: RENT / LEASE AGREEMENT
  // -------------------------------------------------------------
  const hasLeaseContext = /(?:lease\s*agreement|rent\s*agreement|rental\s*agreement|tenancy\s*agreement|commercial\s*lease)/i.test(textSample) ||
    (/(?:lessor|landlord)/i.test(textSample) && /(?:lessee|tenant)/i.test(textSample) && /(?:demised\s*premises|monthly\s*rent|security\s*deposit)/i.test(textSample));
  if (hasLeaseContext && !hasGstForm) {
    return {
      primaryDomain: 'RENT_LEASE_AGREEMENT',
      secondaryDomains: ['PREMISES_AND_ESTABLISHMENT'],
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Commercial Premises Rent / Lease Agreement contract identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 10: SHOPS & ESTABLISHMENT CERTIFICATE
  // -------------------------------------------------------------
  const hasShopsContext = /(?:shops\s*and\s*establishment|shops\s*&\s*establishment|shops\s*act|form\s*c\b|commercial\s*establishment\s*act)/i.test(textSample);
  const shopsRegMatch = textSample.match(/\b(?:SEC|SEA|SHOPS|FORM[-_]?C)[-_#:\s]?[A-Z0-9\-_/]{3,25}\b/i);
  if (hasShopsContext && !hasGstForm && !hasLeaseContext) {
    if (shopsRegMatch) detectedIdentifiers.push(`SHOPS_REG:${shopsRegMatch[0]}`);
    return {
      primaryDomain: 'SHOPS_ESTABLISHMENT_CERTIFICATE',
      secondaryDomains: ['PREMISES_AND_ESTABLISHMENT'],
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Shops and Commercial Establishment Act Registration Certificate identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 11: FIRE DRILL RECENCY
  // -------------------------------------------------------------
  const hasDrillContext = /(?:fire\s*drill|evacuation\s*drill|mock\s*drill|emergency\s*evacuation\s*drill\s*report)/i.test(textSample) ||
    (fnLower.includes('drill') && /(?:drill\s*date|evacuation\s*time|headcount|fire\s*warden)/i.test(textSample));
  if (hasDrillContext) {
    return {
      primaryDomain: 'FIRE_DRILL_RECENCY',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Fire Safety Evacuation Drill event report identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 12: FIRE EXTINGUISHER SAFETY
  // -------------------------------------------------------------
  const hasExtinguisherContext = /(?:fire\s*extinguisher|pressure\s*gauge|cylinder\s*tag|co2\s*extinguisher|abc\s*powder|refill\s*due\s*date|hydrostatic\s*test)/i.test(textSample) ||
    fnLower.includes('extinguisher');
  if (hasExtinguisherContext && !hasDrillContext) {
    return {
      primaryDomain: 'FIRE_EXTINGUISHER_SAFETY',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Fire extinguisher inspection, tagging, and maintenance log identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 13: PF / ESIC & PRINCIPAL EMPLOYER
  // -------------------------------------------------------------
  const hasPfEsic = /(?:provident\s*fund|epfo|esic|employees'?\s*state\s*insurance|epf\s*registration|esic\s*registration)/i.test(textSample);
  const epfoCodeMatch = textSample.match(/\b[A-Z]{2}\/[A-Z0-9]{3,7}\/\d+\b/i) || textSample.match(/\b(?:PF|EPFO)[-_#:\s]*([A-Z0-9]*\d+[A-Z0-9]*)\b/i);
  const esicCodeMatch = textSample.match(/\b\d{17}\b/) || textSample.match(/\b(?:ESIC|ESI)[-_#:\s]*([A-Z0-9]*\d+[A-Z0-9]*)\b/i);
  const hasPeCert = /(?:principal\s*employer|contract\s*labour|form\s*i\b|clra)/i.test(textSample);

  if (hasPfEsic && (epfoCodeMatch || esicCodeMatch || /(?:establishment code|code allocation)/i.test(textSample))) {
    if (epfoCodeMatch) detectedIdentifiers.push(`EPFO:${epfoCodeMatch[0]}`);
    if (esicCodeMatch) detectedIdentifiers.push(`ESIC:${esicCodeMatch[0]}`);
    return {
      primaryDomain: 'PF_ESIC_REGISTRATION',
      secondaryDomains: ['PF_ESIC_PRINCIPAL_EMPLOYER'],
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'EPFO / ESIC Statutory Registration Certificate identified.'
    };
  }

  if (hasPeCert && /(?:certificate of registration of principal employer|registration number)/i.test(textSample)) {
    return {
      primaryDomain: 'PRINCIPAL_EMPLOYER_CERTIFICATE',
      secondaryDomains: ['PF_ESIC_PRINCIPAL_EMPLOYER'],
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Principal Employer Registration Certificate under CLRA Act identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 13B: VISITOR REGISTER
  // -------------------------------------------------------------
  if (/(?:visitor register|visitor log|visitor entry|visitor pass)/i.test(textSample) || fnLower.includes('visitor')) {
    return {
      primaryDomain: 'VISITOR_REGISTER',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Physical Visitor Register log records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 14: INFRASTRUCTURE REDUNDANCY (UPS, ISP, Antivirus)
  // -------------------------------------------------------------
  const hasPowerKeywords = /(?:uninterruptible power supply|\bups\b|power backup|dg set|diesel generator|battery backup|runtime test)/i.test(textSample) || fnLower.includes('ups') || fnLower.includes('power');
  const hasInternetKeywords = /(?:dual wan|internet backup|secondary isp|failover test|broadband redundancy|leased line)/i.test(textSample) || fnLower.includes('isp') || fnLower.includes('internet');
  const hasAntivirusKeywords = /(?:antivirus|endpoint protection|\bedr\b|microsoft defender|crowdstrike|symantec|kaspersky|signature update|real-time protection)/i.test(textSample) || fnLower.includes('antivirus') || fnLower.includes('edr');

  if (hasPowerKeywords && hasInternetKeywords && !fnLower.includes('visitor')) {
    return {
      primaryDomain: 'INFRASTRUCTURE_REDUNDANCY_EDR',
      secondaryDomains: ['POWER_BACKUP', 'INTERNET_BACKUP', 'INFRASTRUCTURE_REDUNDANCY_EDR'],
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Combined Power & Internet redundancy maintenance and failover log identified.'
    };
  }

  if (hasPowerKeywords && !fnLower.includes('visitor')) {
    return {
      primaryDomain: 'POWER_BACKUP',
      secondaryDomains: ['INFRASTRUCTURE_REDUNDANCY_EDR'],
      confidence: 0.94,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Power Backup (UPS / DG Set) operational load and runtime test records identified.'
    };
  }

  if (hasInternetKeywords && !fnLower.includes('visitor')) {
    return {
      primaryDomain: 'INTERNET_BACKUP',
      secondaryDomains: ['INFRASTRUCTURE_REDUNDANCY_EDR'],
      confidence: 0.94,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Secondary Internet / ISP redundancy and failover test records identified.'
    };
  }

  if (hasAntivirusKeywords && !fnLower.includes('visitor')) {
    return {
      primaryDomain: 'ANTIVIRUS_EDR',
      secondaryDomains: ['INFRASTRUCTURE_REDUNDANCY_EDR'],
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Antivirus / EDR central management console protection export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 15: BUSINESS CONTINUITY PLAN (BCP)
  // -------------------------------------------------------------
  if (/(?:business continuity plan|\bbcp\b|disaster recovery plan|\bdrp\b|recovery time objective|\brto\b|recovery point objective|\brpo\b)/i.test(textSample) || fnLower.includes('bcp') || fnLower.includes('continuity')) {
    return {
      primaryDomain: 'BUSINESS_CONTINUITY_PLAN',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: true,
      isImplementation: !isPolicy,
      explanation: 'Business Continuity Plan (BCP) & Disaster Recovery framework document identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 16: ESCALATION MATRIX
  // -------------------------------------------------------------
  if (/(?:escalation matrix|level 1|level 2|level 3|level 4|grievance redressal|turnaround time|\btat\b)/i.test(textSample) || fnLower.includes('escalation')) {
    return {
      primaryDomain: 'ESCALATION_MATRIX',
      secondaryDomains,
      confidence: 0.96,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Customer Grievance & Operational Escalation Matrix hierarchy identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 17: WORKSPACE SEGREGATION
  // -------------------------------------------------------------
  if (/(?:workspace segregation|dedicated bay|calling floor layout|phone lending bay|workstation allocation|floor plan)/i.test(textSample) || fnLower.includes('workspace') || fnLower.includes('floor_plan')) {
    return {
      primaryDomain: 'WORKSPACE_SEGREGATION',
      secondaryDomains,
      confidence: 0.92,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Dedicated calling workspace segregation and bay allocation layout identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 18: AGENT ONBOARDING
  // -------------------------------------------------------------
  if (/(?:agent onboarding|onboarding dossier|kyc verification|background check approval|pre-hire verification|joining report)/i.test(textSample) || fnLower.includes('onboarding')) {
    return {
      primaryDomain: 'AGENT_ONBOARDING',
      secondaryDomains,
      confidence: 0.94,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Agent Onboarding & KYC verification dossier identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 19: AGENCY ID CARD
  // -------------------------------------------------------------
  if (/(?:agency id card|field endorsement card|identity card|id badge|dra endorsement)/i.test(textSample) || fnLower.includes('id_card') || fnLower.includes('badge')) {
    return {
      primaryDomain: 'AGENCY_ID_CARD',
      secondaryDomains,
      confidence: 0.93,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Agency Employee ID Card / Field Endorsement badge records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 20: OFFBOARDING / DEACTIVATION
  // -------------------------------------------------------------
  if (/(?:offboarding|agent termination|account deactivation|id card surrender|exit clearance|ad disablement)/i.test(textSample) || fnLower.includes('offboarding') || fnLower.includes('termination')) {
    return {
      primaryDomain: 'OFFBOARDING_DEACTIVATION',
      secondaryDomains,
      confidence: 0.93,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Agent Offboarding, Exit Clearance, and ID Deactivation records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 21: REFRESHER TRAINING
  // -------------------------------------------------------------
  if (/(?:refresher training|training attendance|training log|dra refresher|assessment score)/i.test(textSample) || fnLower.includes('training')) {
    return {
      primaryDomain: 'REFRESHER_TRAINING',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Refresher Training attendance and assessment log identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 22: PERFORMANCE & NDC
  // -------------------------------------------------------------
  if (/(?:performance evaluation|no demand certificate|\bndc\b|quarterly scorecard|recovery performance)/i.test(textSample) || fnLower.includes('ndc') || fnLower.includes('performance')) {
    return {
      primaryDomain: 'PERFORMANCE_NDC',
      secondaryDomains,
      confidence: 0.94,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Agent Performance Evaluation & No Demand Certificate (NDC) record identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 23: SCREEN CAPTURE RESTRICTION (Snipping Tool / MS Paint)
  // -------------------------------------------------------------
  if (/(?:snipping tool|mspaint|screen capture|screenshot restriction|snippingtool\.exe)/i.test(textSample) || fnLower.includes('snipping') || fnLower.includes('screen_capture')) {
    return {
      primaryDomain: 'SCREEN_CAPTURE_RESTRICTION',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Snipping Tool & Screen Capture technical restriction GPO export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 24: PASSWORD POLICY
  // -------------------------------------------------------------
  if (/(?:password policy|lockout threshold|minimum password length|password complexity|ad password gpo)/i.test(textSample) || fnLower.includes('password')) {
    return {
      primaryDomain: 'PASSWORD_POLICY',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Active Directory Password Policy & Account Lockout GPO export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 25: OS PATCH MANAGEMENT
  // -------------------------------------------------------------
  if (/(?:os patch|windows update|\bwsus\b|\bsccm\b|patch compliance|os build)/i.test(textSample) || fnLower.includes('patch') || fnLower.includes('os_update')) {
    return {
      primaryDomain: 'OS_PATCH_MANAGEMENT',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Windows OS Patch Management & WSUS update compliance export identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 26: HR & POSH POLICY
  // -------------------------------------------------------------
  if (/(?:posh policy|sexual harassment|internal complaints committee|\bicc\b|posh annual report)/i.test(textSample) || fnLower.includes('posh') || fnLower.includes('harassment')) {
    return {
      primaryDomain: 'HR_POSH_POLICY',
      secondaryDomains,
      confidence: 0.95,
      detectedIdentifiers,
      isPolicy: true,
      isImplementation: !isPolicy,
      explanation: 'HR & Prevention of Sexual Harassment (POSH) policy document identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 27: VISITOR REGISTER
  // -------------------------------------------------------------
  if (/(?:visitor register|visitor log|visitor entry|visitor pass)/i.test(textSample) || fnLower.includes('visitor')) {
    return {
      primaryDomain: 'VISITOR_REGISTER',
      secondaryDomains,
      confidence: 0.94,
      detectedIdentifiers,
      isPolicy: false,
      isImplementation: true,
      explanation: 'Physical Visitor Register log records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 28: CLEAN DESK
  // -------------------------------------------------------------
  if (/(?:clean desk|nightly sweep|clean desk declaration|clean desk audit)/i.test(textSample) || fnLower.includes('clean_desk')) {
    return {
      primaryDomain: 'CLEAN_DESK',
      secondaryDomains,
      confidence: 0.93,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Clean Desk inspection and compliance declaration records identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 29: CODE OF CONDUCT / DISCIPLINARY
  // -------------------------------------------------------------
  if (/(?:code of conduct|disciplinary action|misconduct breach|incident register|show cause)/i.test(textSample) || fnLower.includes('misconduct') || fnLower.includes('disciplinary')) {
    return {
      primaryDomain: 'CODE_OF_CONDUCT_DISCIPLINARY',
      secondaryDomains,
      confidence: 0.92,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Code of Conduct & Agent Disciplinary Incident register identified.'
    };
  }

  // -------------------------------------------------------------
  // DOMAIN 30: STAFF ATTIRE
  // -------------------------------------------------------------
  if (/(?:staff attire|dress code|grooming standard)/i.test(textSample) || fnLower.includes('attire')) {
    return {
      primaryDomain: 'STAFF_ATTIRE',
      secondaryDomains,
      confidence: 0.90,
      detectedIdentifiers,
      isPolicy,
      isImplementation: !isPolicy,
      explanation: 'Staff Attire & Dress Code compliance register identified.'
    };
  }

  return {
    primaryDomain: 'UNASSIGNED',
    secondaryDomains,
    confidence: 0.50,
    detectedIdentifiers,
    isPolicy,
    isImplementation,
    explanation: 'Unassigned domain — document does not contain recognizable domain-specific structural compliance markers.'
  };
}

/**
 * Asserts whether a document's classified domain matches the target audit control or sub-control domain.
 */
export function assertEvidenceDomainMatchesControl(
  controlDomain: EvidenceDomain,
  documentDomain: EvidenceDomain,
  allowedDomains: EvidenceDomain[] = []
): boolean {
  if (!controlDomain || !documentDomain) return false;
  if (documentDomain === 'UNASSIGNED' || documentDomain === 'TEST_METADATA_DOMAIN') return false;

  // Direct match
  if (controlDomain === documentDomain) return true;

  // Explicit allowed domains
  if (allowedDomains.includes(documentDomain)) return true;

  // Hierarchical / Compound relationships:
  // PREMISES_AND_ESTABLISHMENT encompasses RENT_LEASE_AGREEMENT and SHOPS_ESTABLISHMENT_CERTIFICATE
  if (
    (controlDomain === 'PREMISES_AND_ESTABLISHMENT' &&
      (documentDomain === 'RENT_LEASE_AGREEMENT' || documentDomain === 'SHOPS_ESTABLISHMENT_CERTIFICATE')) ||
    (documentDomain === 'PREMISES_AND_ESTABLISHMENT' &&
      (controlDomain === 'RENT_LEASE_AGREEMENT' || controlDomain === 'SHOPS_ESTABLISHMENT_CERTIFICATE'))
  ) {
    return true;
  }

  // ENDPOINT_DATA_RESTRICTION encompasses ENDPOINT_SECURITY_POLICY and ENDPOINT_DATA_RESTRICTION_CONFIG
  if (
    (controlDomain === 'ENDPOINT_DATA_RESTRICTION' &&
      (documentDomain === 'ENDPOINT_SECURITY_POLICY' || documentDomain === 'ENDPOINT_DATA_RESTRICTION_CONFIG')) ||
    (documentDomain === 'ENDPOINT_DATA_RESTRICTION' &&
      (controlDomain === 'ENDPOINT_SECURITY_POLICY' || controlDomain === 'ENDPOINT_DATA_RESTRICTION_CONFIG'))
  ) {
    return true;
  }

  // WEB_COMMUNICATION_FILTERING encompasses WEB_FILTERING_POLICY and WEB_COMMUNICATION_FILTERING_CONFIG
  if (
    (controlDomain === 'WEB_COMMUNICATION_FILTERING' &&
      (documentDomain === 'WEB_FILTERING_POLICY' || documentDomain === 'WEB_COMMUNICATION_FILTERING_CONFIG')) ||
    (documentDomain === 'WEB_COMMUNICATION_FILTERING' &&
      (controlDomain === 'WEB_FILTERING_POLICY' || controlDomain === 'WEB_COMMUNICATION_FILTERING_CONFIG'))
  ) {
    return true;
  }

  // CCTV_SURVEILLANCE_RETENTION encompasses CCTV_INSTALLATION and CCTV_RETENTION_CONFIG
  if (
    (controlDomain === 'CCTV_SURVEILLANCE_RETENTION' &&
      (documentDomain === 'CCTV_INSTALLATION' || documentDomain === 'CCTV_RETENTION_CONFIG')) ||
    (documentDomain === 'CCTV_SURVEILLANCE_RETENTION' &&
      (controlDomain === 'CCTV_INSTALLATION' || controlDomain === 'CCTV_RETENTION_CONFIG'))
  ) {
    return true;
  }

  // PF_ESIC_PRINCIPAL_EMPLOYER encompasses PF_ESIC_REGISTRATION and PRINCIPAL_EMPLOYER_CERTIFICATE
  if (
    (controlDomain === 'PF_ESIC_PRINCIPAL_EMPLOYER' &&
      (documentDomain === 'PF_ESIC_REGISTRATION' || documentDomain === 'PRINCIPAL_EMPLOYER_CERTIFICATE')) ||
    (documentDomain === 'PF_ESIC_PRINCIPAL_EMPLOYER' &&
      (controlDomain === 'PF_ESIC_REGISTRATION' || controlDomain === 'PRINCIPAL_EMPLOYER_CERTIFICATE'))
  ) {
    return true;
  }

  // INFRASTRUCTURE_REDUNDANCY_EDR encompasses POWER_BACKUP, INTERNET_BACKUP, ANTIVIRUS_EDR
  if (
    (controlDomain === 'INFRASTRUCTURE_REDUNDANCY_EDR' &&
      (documentDomain === 'POWER_BACKUP' || documentDomain === 'INTERNET_BACKUP' || documentDomain === 'ANTIVIRUS_EDR')) ||
    (documentDomain === 'INFRASTRUCTURE_REDUNDANCY_EDR' &&
      (controlDomain === 'POWER_BACKUP' || controlDomain === 'INTERNET_BACKUP' || controlDomain === 'ANTIVIRUS_EDR'))
  ) {
    return true;
  }

  return false;
}
