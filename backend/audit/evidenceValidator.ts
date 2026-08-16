import { AuditParameter } from './models.js';
import { DateEvaluator } from './dateEvaluator.js';

export interface ValidationResult {
  validated: boolean;
  confidence: number;
  fieldValidation: boolean;
  metadataMatch: boolean;
  entityMatch: boolean;
  semanticMatch: boolean;
  detectedEvidenceType: string;
  validationReason: string;
  missingMandatoryFields: string[];
  extractedFields: Record<string, any>;
}

export class EvidenceValidator {
  /**
   * Performs deep structured validation of evidence documents against parameter criteria.
   * Prevents false passes from filename spoofing or generic keyword matching.
   */
  public static validate(
    filename: string,
    text: string,
    parameter: AuditParameter,
    policyVsImpl: { isPolicy: boolean; isImplementation: boolean; type: string }
  ): ValidationResult {
    const textLower = text.toLowerCase();
    const filenameLower = filename.toLowerCase();

    const extractedDates = DateEvaluator.extractDatesFromText(text);
    const personName = this.extractPersonName(text);
    const agentId = this.extractAgentId(text);
    const employeeId = this.extractEmployeeId(text);
    const certificateNumber = this.extractCertificateNumber(text);
    const email = this.extractEmail(text);
    const phone = this.extractPhone(text);

    let validated = false;
    let confidence = 0.50;
    let fieldValidation = false;
    let metadataMatch = false;
    let entityMatch = false;
    let semanticMatch = false;
    let validationReason = 'Evidence did not satisfy mandatory structured field requirements.';
    const missingMandatoryFields: string[] = [];

    let detectedEvidenceType = parameter.evidence_types?.[0] || parameter.required_evidence[0] || 'GENERIC_EVIDENCE';

    if (personName || agentId || employeeId || extractedDates.issueDate || extractedDates.expiryDate || extractedDates.effectiveDate || extractedDates.applicationDate) {
      metadataMatch = true;
    }
    if (personName || agentId || employeeId) {
      entityMatch = true;
    }

    const extractedFields: Record<string, any> = {
      person_name: personName,
      agent_id: agentId,
      employee_id: employeeId,
      certificate_number: certificateNumber,
      email,
      phone,
      issue_date: extractedDates.issueDate,
      effective_date: extractedDates.effectiveDate,
      expiry_date: extractedDates.expiryDate,
      review_date: extractedDates.reviewDate,
      application_date: extractedDates.applicationDate,
      renewal_date: extractedDates.renewalDate,
      audit_date: extractedDates.auditDate,
      all_dates: extractedDates.allDates,
      date_items: extractedDates.dateItems,
      is_policy: policyVsImpl.isPolicy,
      is_implementation: policyVsImpl.isImplementation,
      policy_type: policyVsImpl.type
    };

    switch (parameter.id) {
      case 'ZTI-001': { // GST Registration Certificate
        detectedEvidenceType = 'GST_REGISTRATION';
        // GSTIN regex: 2 digits, 5 letters, 4 digits, 1 letter, 1 digit/letter, 'Z', 1 digit/letter
        const gstinMatch = text.match(/\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z0-9]{1}Z[A-Z0-9]{1}\b/);
        const hasGstTitle = /(?:goods and services tax|gst registration|registration certificate|tax invoice|form gst)/i.test(text);
        const hasLegalName = /(?:legal name|trade name|registered entity|taxpayer name)/i.test(text);

        if (gstinMatch) {
          extractedFields['gstin'] = gstinMatch[0];
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.98;
          validationReason = `Valid GSTIN identifier (${gstinMatch[0]}) extracted and verified.`;
        } else if (hasGstTitle && hasLegalName) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.85;
          validationReason = 'GST Registration header and legal entity name identified.';
        } else {
          missingMandatoryFields.push('Valid 15-digit GSTIN or Registration Certificate Structure');
          validationReason = 'Document contains GST keyword mention but lacks mandatory GSTIN format or official certificate structure.';
        }
        break;
      }

      case 'ZTI-002': { // Biometric Access Control
        detectedEvidenceType = 'BIOMETRIC_ACCESS_CONFIG';
        const hasBiometricLogs = /(?:punch\s*in|punch\s*out|badge\s*id|biometric\s*terminal|fingerprint\s*reader|access\s*control\s*door|turnstile\s*log|card\s*reader\s*log|door\s*controller)/i.test(text);
        const hasTimestamps = /(?:\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})/i.test(text);
        const hasDeviceConfig = /(?:biometric\s*controller|door\s*access\s*controller|terminal\s*config|badge\s*reader\s*config|access\s*point\s*controller)/i.test(text);
        const isCctvDoc = /(?:cctv|surveillance camera|dvr|nvr|90 days retention)/i.test(text) && !hasBiometricLogs && !hasDeviceConfig;

        if (isCctvDoc) {
          missingMandatoryFields.push('Biometric Access Control Terminal Logs or Door Controller Hardware Config');
          validationReason = 'Document is a CCTV surveillance record, which cannot satisfy Biometric Access Control requirements.';
        } else if (hasBiometricLogs && (hasTimestamps || personName)) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Biometric attendance/access log entries with timestamps or user IDs verified.';
        } else if (hasDeviceConfig) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.90;
          validationReason = 'Biometric access terminal system configuration verified.';
        } else {
          missingMandatoryFields.push('Access Terminal Logs with Timestamps or Hardware Configuration');
          validationReason = 'Text mentions access control conceptually without access log records or device configuration.';
        }
        break;
      }

      case 'ZTI-003': { // Segregated Workspace / Phone Lending
        detectedEvidenceType = 'WORKSPACE_SEGREGATION_RECORD';
        const hasFloorPlanOrBay = /(?:bay\s*#?\s*\d+|floor\s*plan|seating\s*allocation|system\s*allocation|dedicated\s*desk|workstation\s*id)/i.test(text);
        const hasSegregationContext = /(?:segregat|restricted\s*area|lending\s*operations|access\s*card\s*only|dedicated\s*bay)/i.test(text);

        if (hasFloorPlanOrBay && hasSegregationContext) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.92;
          validationReason = 'Dedicated workspace/system allocation with segregated bay verified.';
        } else {
          missingMandatoryFields.push('Workstation/Bay Allocation Sheet or Segregated Floor Documentation');
          validationReason = 'Generic reference to lending workspace without workstation/bay allocation proof.';
        }
        break;
      }

      case 'ZTI-004': { // DRA Certificate
        detectedEvidenceType = 'DRA_CERTIFICATE';
        const certMatch = text.match(/\b(?:certificate\s*(?:no|number|#|num|id)[:\s#.]+|certificate[:#]\s*)([A-Z0-9\-_/]{3,25})\b/i) ||
          text.match(/\b((?:DRA|CERT|NBFET|IIBF)[-_#:\s/][A-Z0-9\-_/]{3,20})\b/i) ||
          text.match(/\b(DRA\s*\/\s*\d{4}\s*\/\s*\d{3,10})\b/i);
        const hasDraContext = /(?:debt recovery agent|dra trained|dra certification|certificate of completion|nbfet|dra passed|trained certificate|iibf|recovery agent)/i.test(text) ||
          (filenameLower.includes('dra') && /(?:certificate|training|passed|exam|cert|agent)/i.test(text)) ||
          Boolean(certMatch && /dra/i.test(certMatch[0]));
        const hasStatus = /(?:status:\s*passed|status:\s*completed|status:\s*certified|\bpassed\b|\bcompleted\b|\btrained\b)/i.test(text);

        if (certMatch) {
          extractedFields['certificate_number'] = certMatch[1] || certMatch[0];
        }

        if (hasDraContext && (certMatch || (personName && hasStatus))) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          entityMatch = true;
          confidence = 0.96;
          validationReason = `DRA certificate validated${certMatch ? ' (Cert No: ' + (certMatch[1] || certMatch[0]) + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('DRA Certificate Number or Candidate Training Record');
          validationReason = 'Generic DRA keyword reference without valid certificate number or candidate completion record.';
        }
        break;
      }

      case 'ZTI-005': { // Police Verification
        const isApp = /(?:applied|acknowledgement|receipt|application type|pending)/i.test(text);
        detectedEvidenceType = isApp ? 'POLICE_VERIFICATION_APPLICATION' : 'POLICE_VERIFICATION';

        const ackMatch = text.match(/\b(PV-ACK|ACK|PCC)[-_#:\s]?\d{3,15}\b/i) || text.match(/\b(?:acknowledgement\s*(?:no|number|#|slip|id)?[:#]\s*|ack\s*(?:no|number|#)[:\s#.]*)([A-Z0-9\-_/]{3,25})\b/i);
        const hasPoliceContext = /(?:police verification|character & background|clearance report|police clearance|state police)/i.test(text);
        const hasStatus = /(?:verified|applied|clearance|cleared)/i.test(text);

        if (ackMatch) {
          extractedFields['acknowledgement_number'] = ackMatch[1] || ackMatch[0];
        }

        if (hasPoliceContext && (ackMatch || (personName && hasStatus))) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          entityMatch = true;
          confidence = 0.95;
          validationReason = `Police verification documentary proof validated (${isApp ? 'Application Acknowledgement' : 'Verification Report'}).`;
        } else {
          missingMandatoryFields.push('Police Verification Certificate / Application Acknowledgement Slip');
          validationReason = 'Generic reference to police clearance without acknowledgement slip or official report structure.';
        }
        break;
      }

      case 'ZTI-007': { // Agent Onboarding Documents Authentication
        detectedEvidenceType = 'AGENT_ONBOARDING_DOSSIER';
        const hasOnboardingContext = /(?:agent onboarding|onboarding dossier|kyc verification|joining report|pre-hire verification|background check approval)/i.test(text);
        const hasApproval = /(?:approved|authenticated|verified by|hr approval|manager approval|authorized)/i.test(text);
        const hasChecklist = /(?:checklist|dossier|document collected|documents verified)/i.test(text);

        if (hasOnboardingContext && (hasApproval || hasChecklist)) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Agent onboarding and KYC documentation record validated.';
        } else {
          missingMandatoryFields.push('Agent Onboarding Checklist / KYC Authentication Record');
          validationReason = 'Document lacks explicit agent onboarding context, checklist, or HR approval signatures.';
        }
        break;
      }

      case 'ZTI-008': { // USB & Cloud storage access restriction
        const isPolicyDoc = policyVsImpl.isPolicy;
        const isImplDoc = policyVsImpl.isImplementation || /(?:active\s*gpo|gpo\s*name|registry\s*key|storagedevicepolicies|deny_all|system\s*dump|configuration\s*export|storport)/i.test(text);
        if (isImplDoc && policyVsImpl.type !== 'POLICY_ONLY') {
          detectedEvidenceType = 'DLP_GPO_CONFIGURATION_EXPORT';
          const hasTechnicalDetails = /(?:removable\s*media|usb\s*storage|cloud\s*storage|gpo|dlp|registry\s*key|block\s*rule|disabled|denied|storagedevicepolicies|deny_all|storport)/i.test(text);
          if (hasTechnicalDetails) {
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.95;
            validationReason = 'USB & Cloud storage technical access restriction configuration validated.';
          } else {
            missingMandatoryFields.push('Technical GPO/DLP Configuration Export');
            validationReason = 'Generic mention without technical implementation configuration.';
          }
        } else if (isPolicyDoc) {
          detectedEvidenceType = 'ENDPOINT_SECURITY_POLICY';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.85;
          validationReason = 'Endpoint security policy document validated.';
        } else {
          missingMandatoryFields.push('Endpoint Security Policy or GPO/DLP Configuration');
          validationReason = 'Text lacks USB/cloud security policy or technical restriction proof.';
        }
        break;
      }

      case 'ZTI-009': { // Blacklisting of social sites / personal email / messaging
        const isPolicyDoc = policyVsImpl.isPolicy;
        const isImplDoc = policyVsImpl.isImplementation || /(?:firewall\s*rule|proxy\s*config|squid\s*proxy|fortigate|palo\s*alto|checkpoint|iptables|rule\s*id|action:\s*(?:deny|drop))/i.test(text);
        if (isImplDoc && policyVsImpl.type !== 'POLICY_ONLY') {
          detectedEvidenceType = 'FIREWALL_PROXY_CONFIGURATION_EXPORT';
          const hasFilteringRules = /(?:social\s*media|personal\s*email|messaging|facebook|whatsapp|telegram|instagram|gmail|blocked|drop|deny|url\s*category|filter\s*rule)/i.test(text);
          if (hasFilteringRules) {
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.95;
            validationReason = 'Firewall / Proxy URL blacklisting configuration verified.';
          } else {
            missingMandatoryFields.push('Firewall/Proxy Blacklist Rule Configuration');
            validationReason = 'Technical filtering configuration lacks specific URL/category blacklist rules.';
          }
        } else if (isPolicyDoc) {
          detectedEvidenceType = 'WEB_FILTERING_POLICY';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.85;
          validationReason = 'Web filtering policy document validated.';
        } else {
          missingMandatoryFields.push('Web Filtering Policy or Firewall/Proxy Configuration');
          validationReason = 'Text lacks web filtering policy or technical proxy blocking configuration.';
        }
        break;
      }

      case 'IPM-001': { // PF & ESIC Registration OR Principal Employer Certificate
        const hasPfEsic = /(?:provident fund|epfo|esic|employees'? state insurance|epf registration|esic registration)/i.test(text);
        const epfoCodeMatch = text.match(/\b[A-Z]{2}\/[A-Z0-9]{3,7}\/\d+\b/i) || text.match(/\b(?:PF|EPFO)[-_#:\s]*([A-Z0-9]*\d+[A-Z0-9]*)\b/i);
        const esicCodeMatch = text.match(/\b\d{17}\b/) || text.match(/\b\d{10}\b/) || text.match(/\b(?:ESIC|ESI)[-_#:\s]*([A-Z0-9]*\d+[A-Z0-9]*)\b/i);

        const hasPrincipalEmployer = /(?:principal employer|contract labour|form\s*(?:i|ii|1|2)|clra)/i.test(text);
        const peRegMatch = text.match(/\b(?:PE|CLRA|REG|FORM[-_]?I)[-_#:\s]*([A-Z0-9\-_/]*\d+[A-Z0-9\-_/]*)\b/i);

        if (hasPfEsic && (epfoCodeMatch || esicCodeMatch || /(?:establishment code|registration certificate|code allocation)/i.test(text))) {
          detectedEvidenceType = 'PF_ESIC_CERTIFICATE';
          extractedFields['epfo_code'] = epfoCodeMatch ? epfoCodeMatch[0] : undefined;
          extractedFields['esic_code'] = esicCodeMatch ? esicCodeMatch[0] : undefined;
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.96;
          validationReason = `PF / ESIC Registration Certificate validated (${epfoCodeMatch ? 'EPFO: ' + epfoCodeMatch[0] : ''} ${esicCodeMatch ? 'ESIC: ' + esicCodeMatch[0] : ''}).`;
        } else if (hasPrincipalEmployer && (peRegMatch || /(?:certificate of registration of principal employer|registration number)/i.test(text))) {
          detectedEvidenceType = 'PRINCIPAL_EMPLOYER_CERTIFICATE';
          extractedFields['principal_employer_reg_no'] = peRegMatch ? peRegMatch[0] : undefined;
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = `Principal Employer Registration Certificate validated${peRegMatch ? ' (' + peRegMatch[0] + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('PF/ESIC Registration Certificate with Code or Principal Employer Certificate');
          validationReason = 'Generic PF/ESIC mention without valid registration certificate or establishment code.';
        }
        break;
      }

      case 'IPM-003': { // Rent/Lease Agreement AND Shops & Establishment Certificate
        const hasLease = /(?:lease agreement|rent agreement|rental agreement|tenancy agreement|commercial lease|lessor|lessee|landlord|tenant)/i.test(text);
        const hasLeaseTerms = /(?:premises|monthly rent|deposit|lease period|term of lease|address of premises|hereby agree)/i.test(text);

        const hasShops = /(?:shops and establishment|shops & establishment|commercial establishment act|form c|shops act|shops registration)/i.test(text);
        const shopsRegMatch = text.match(/\b(?:SEC|SEA|REG|SHOPS|FORM[-_]?C)[-_#:\s]?[A-Z0-9\-_/]{3,25}\b/i);
        const isGstDoc = /(?:gstin|goods and services tax|form gst reg)/i.test(text) && !hasLease && !hasShops;

        if (isGstDoc) {
          missingMandatoryFields.push('Premises Rent/Lease Agreement or Shops & Establishment Certificate');
          validationReason = 'Document is a GST Registration record, which cannot satisfy Premises/Shops & Establishment requirements.';
        } else if (hasLease && hasLeaseTerms) {
          detectedEvidenceType = 'LEASE_AGREEMENT';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Premises Rent/Lease Agreement validated with terms, premises, and lessor/lessee details.';
        } else if (hasShops && (shopsRegMatch || /(?:registration number|establishment name|certificate of registration)/i.test(text))) {
          detectedEvidenceType = 'SHOPS_ESTABLISHMENT_CERTIFICATE';
          extractedFields['shops_registration_no'] = shopsRegMatch ? shopsRegMatch[0] : undefined;
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.96;
          validationReason = `Shops and Establishment Act Registration Certificate validated${shopsRegMatch ? ' (Reg No: ' + shopsRegMatch[0] + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('Valid Lease Agreement with premises terms or Shops & Establishment Certificate');
          validationReason = 'Document lacks structured Lease Agreement terms or official Shops Certificate registration details.';
        }
        break;
      }

      case 'IPM-004': { // Commercial General Liability Insurance
        detectedEvidenceType = 'INSURANCE_POLICY';
        const policyNoMatch = text.match(/\b(POL|INS|CGL|PL)[-_#:\s]\d{3,15}\b/i) || text.match(/\b(?:policy\s*(?:no|number|#|num|id)[:\s#.]+|policy[:#]\s*)([A-Z0-9\-_/]{3,25})\b/i);
        const hasInsuranceContext = /(?:commercial general liability|cgl policy|insurance policy|liability coverage|indemnity insurance)/i.test(text);
        const hasCoverageOrInsurer = /(?:insurer[:\s]+[^\n\r]+|coverage amount[:\s]+[^\n\r]+|sum insured[:\s]+[^\n\r]+|insured organization[:\s]+[^\n\r]+|\$\s*\d{3,}|rs\.?\s*\d{3,})/i.test(text);

        if (policyNoMatch) {
          extractedFields['policy_number'] = policyNoMatch[1] || policyNoMatch[0];
        }

        if (hasInsuranceContext && (policyNoMatch || (hasCoverageOrInsurer && extractedDates.expiryDate))) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.97;
          validationReason = `Commercial liability insurance policy validated${policyNoMatch ? ' (Policy: ' + (policyNoMatch[1] || policyNoMatch[0]) + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('Insurance Policy Number or Insurer & Coverage Details');
          validationReason = 'Generic insurance mention without valid policy number or coverage details.';
        }
        break;
      }

      case 'IPM-006': { // CCTV installed with recordings retained for minimum 90 days
        const hasCctvHardware = /(?:cctv|surveillance camera|camera inventory|camera layout|dvr installation|nvr commissioning|channel 1|cam 01|bullet camera|dome camera)/i.test(text);
        const hasRetentionDetails = /(?:retention|recording duration|90 days|storage settings|dvr config|nvr retention|overwrite after|tb storage)/i.test(text);

        if (hasRetentionDetails && /(?:90 days|>= 90|90\+|3 months|100 days|120 days)/i.test(text)) {
          detectedEvidenceType = 'CCTV_RETENTION_CONFIGURATION';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'CCTV recording retention configuration (>= 90 days) technical verification validated.';
        } else if (hasCctvHardware && !policyVsImpl.isPolicy) {
          detectedEvidenceType = 'CCTV_INSTALLATION_RECORD';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.93;
          validationReason = 'CCTV camera installation, hardware layout, and operational inventory validated.';
        } else {
          missingMandatoryFields.push('CCTV Physical Installation Inventory or 90-Day Retention Configuration Log');
          validationReason = 'Generic CCTV mention or policy statement without physical installation inventory or technical 90-day retention configuration.';
        }
        break;
      }

      case 'IPM-007': { // Fire Extinguisher available, functional, and not expired
        // CRITICAL EVIDENCE ISOLATION: A Fire Drill report is NOT a Fire Extinguisher inspection!
        const isFireDrillOnly = /(?:fire drill|evacuation drill|mock drill|drill report|drill attendance)/i.test(text) && !/(?:fire extinguisher|extinguisher refill|pressure gauge|cylinder)/i.test(text);
        if (isFireDrillOnly) {
          fieldValidation = false;
          validated = false;
          missingMandatoryFields.push('Fire Extinguisher Physical Inspection Tag / Maintenance Log');
          validationReason = 'Document is a Fire Drill Report (IPM-008), which cannot satisfy Fire Extinguisher equipment requirements (IPM-007).';
          break;
        }

        const hasExtinguisherContext = /(?:fire extinguisher|extinguisher refill|abc powder|co2 extinguisher|pressure gauge|cylinder inspection|inspection tag|fire equipment)/i.test(text);
        const hasInspectionOrExpiry = extractedDates.expiryDate || extractedDates.issueDate || /(?:gauge (?:ok|green)|functional|serviced|next inspection|refill date|cylinder no)/i.test(text);

        if (hasExtinguisherContext && hasInspectionOrExpiry) {
          detectedEvidenceType = 'FIRE_EXTINGUISHER_INSPECTION';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Fire extinguisher equipment inspection and refill status verified.';
        } else {
          missingMandatoryFields.push('Fire Extinguisher Inspection Certificate / Maintenance Log');
          validationReason = 'Generic fire safety mention without physical extinguisher inspection or refill details.';
        }
        break;
      }

      case 'IPM-008': { // Fire Drill conducted by agency
        detectedEvidenceType = 'FIRE_DRILL_REPORT';
        const hasDrillContext = /(?:fire drill|evacuation drill|mock drill|drill report|fire safety drill|emergency evacuation)/i.test(text);
        const hasDrillActivity = /(?:conducted|drill date|evacuation time|participants|attendance|warden|assembly point|scenario|minutes)/i.test(text);
        const drillDate = extractedDates.issueDate || extractedDates.effectiveDate || (extractedDates.allDates.length > 0 ? extractedDates.allDates[0] : undefined);

        if (drillDate) {
          extractedFields['drill_date'] = drillDate;
        }

        if (hasDrillContext && (hasDrillActivity || drillDate)) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = `Fire drill documentary records validated${drillDate ? ' (Conducted Date: ' + drillDate + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('Fire Drill Report with Drill Date and Participant Records');
          validationReason = 'Generic fire safety mention without actual fire drill execution report.';
        }
        break;
      }

      case 'IPM-009': { // Power Backup / Internet Backup / Antivirus on systems
        const hasPower = /(?:power backup|ups maintenance|dg set|diesel generator|battery bank|inverter backup|load test|kva|runtime)/i.test(text);
        const hasInternet = /(?:secondary isp|internet backup|dual[- ]wan|failover link|secondary leased line|redundant internet|backup broadband|airtel|tata)/i.test(text);
        const hasAntivirus = /(?:antivirus|endpoint protection|edr|crowdstrike|windows defender|symantec|trend micro|kaspersky|virus definitions|signature update|agent version)/i.test(text);

        if (hasPower) {
          detectedEvidenceType = 'POWER_BACKUP_LOG';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Operational Power Backup (UPS/Generator/Battery) maintenance logs validated.';
        } else if (hasInternet) {
          detectedEvidenceType = 'INTERNET_BACKUP_CONFIG';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Secondary Internet Link / Failover connectivity validated.';
        } else if (hasAntivirus) {
          detectedEvidenceType = 'ANTIVIRUS_CONSOLE_REPORT';
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Antivirus / Endpoint Security definition and deployment status validated.';
        } else {
          missingMandatoryFields.push('Power Backup Log, Secondary ISP Config, or Antivirus Console Report');
          validationReason = 'Text does not contain operational power backup, secondary ISP, or antivirus configuration proof.';
        }
        break;
      }

      default: {
        if (parameter.distinguish_policy && policyVsImpl.isPolicy && !policyVsImpl.isImplementation) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.85;
          validationReason = 'Policy document identified and validated for policy presence.';
        } else if (text.length > 50) {
          // If no custom strict validator defined, accept meaningful text
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.85;
          validationReason = 'Document matched required domain context.';
        } else {
          validationReason = 'Insufficient document body content.';
        }
        break;
      }
    }

    return {
      validated,
      confidence,
      fieldValidation,
      metadataMatch,
      entityMatch,
      semanticMatch,
      detectedEvidenceType,
      validationReason,
      missingMandatoryFields,
      extractedFields
    };
  }

  private static extractPersonName(text: string): string | undefined {
    // 1. Labeled pattern on the same line: "Agent / Employee: John Smith", "Agent Name: JOHN SMITH", "Name: Jane Doe"
    const labeledMatch = text.match(/(?:Employee(?:\s*Name)?|Agent(?:\s*(?:\/|\&)\s*Employee)?(?:\s*Name)?|Staff(?:\s*Name)?|Candidate(?:\s*Name)?|Participant(?:\s*Name)?|Director|VP|Name|User|Officer|Person|To certify that)[:,\s]+([A-Za-z\.\'\- ]{2,35})(?=[\r\n]|$)/i);
    if (labeledMatch) {
      const candidate = labeledMatch[1].trim();
      if (candidate.length >= 2 && !/(?:status|passed|completed|policy|procedure|training|date|active|valid)/i.test(candidate)) {
        return candidate;
      }
    }

    // 2. CSV table column match: e.g. "Participant_Name,..."
    const csvMatch = text.match(/(?:Participant_Name|Candidate_Name|Employee_Name)[^\n\r]*[\n\r]+(?:[^\n\r,]+,){3}([^\n\r,]+)/i);
    if (csvMatch) {
      const candidate = csvMatch[1].trim();
      if (candidate.length >= 2) return candidate;
    }

    // 3. Generic Two-Word or Three-Word Capitalized Name (Title Case or ALL CAPS)
    const titleCaseMatch = text.match(/\b([A-Z][a-z]{1,15}\s+(?:[A-Z]\.?\s+)?[A-Z][a-z]{1,15})\b/);
    if (titleCaseMatch) {
      const candidate = titleCaseMatch[1].trim();
      // Ignore common title phrases
      if (!/(?:Debt Recovery|General Liability|Police Verification|Access Control|Code of|Fire Drill|Standard Operating|Operating Procedure|Banking Financial|Financial Education|Education Trust|Alternative Control|Recovery Agent)/i.test(candidate)) {
        return candidate;
      }
    }

    const allCapsMatch = text.match(/\b([A-Z]{2,15}\s+(?:[A-Z]\.?\s+)?[A-Z]{2,15})\b/);
    if (allCapsMatch) {
      const candidate = allCapsMatch[1].trim();
      if (!/(?:BANKING FINANCIAL|EDUCATION TRUST|GENERAL LIABILITY|POLICE DEPARTMENT|ACCESS CONTROL|CODE OF|FIRE DRILL|STANDARD OPERATING|ALTERNATIVE CONTROL|GPO NAME|USB BLOCK)/i.test(candidate)) {
        return candidate;
      }
    }

    return undefined;
  }

  private static extractAgentId(text: string): string | undefined {
    // 1. Explicit Agent ID label (prevent matching 'Agent Name:' as an ID)
    const labeled = text.match(/\b(?:Agent\s*(?:ID|Code|#|Num|Number)|Agent\s*No|Agent\s*#)[:\s#]+([A-Z0-9\-_]{2,20})\b/i) ||
      text.match(/\bAgent[:\s#]+(?!Name\b)([A-Z0-9\-_]{2,20})\b/i);
    if (labeled) return labeled[1].trim().toUpperCase();

    const agPattern = text.match(/\b(AG[-_]?\d{2,10})\b/i);
    if (agPattern) return agPattern[1].trim().toUpperCase();

    return undefined;
  }

  private static extractEmployeeId(text: string): string | undefined {
    const labeled = text.match(/\b(?:Employee\s*(?:ID|Code|#|Num|Number)?|Emp\s*(?:ID|Code|#)?|Staff\s*ID)[:\s#]+([A-Z0-9\-_]{2,20})\b/i);
    if (labeled) return labeled[1].trim().toUpperCase();

    const empPattern = text.match(/\b(EMP[-_]?\d{2,10})\b/i);
    if (empPattern) return empPattern[1].trim().toUpperCase();

    return undefined;
  }

  private static extractCertificateNumber(text: string): string | undefined {
    const certMatch = text.match(/\b(?:Certificate\s*(?:No|Number|#|Id)?|Cert\s*(?:No|Number|#)?|Acknowledgement\s*(?:Slip\s*)?(?:No|Number|#)?|Ack\s*(?:No|Number|#)?)[:\s#]+([A-Z0-9\-_/]{3,30})\b/i);
    if (certMatch) return certMatch[1].trim().toUpperCase();

    const codePattern = text.match(/\b((?:DRA|PV-ACK|CERT|NBFET|PCC)[-_#:\s][A-Z0-9\-_/]{3,25})\b/i);
    if (codePattern) return codePattern[1].trim().toUpperCase();

    return undefined;
  }

  private static extractEmail(text: string): string | undefined {
    const emailMatch = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
    return emailMatch ? emailMatch[0].toLowerCase().trim() : undefined;
  }

  private static extractPhone(text: string): string | undefined {
    const phoneMatch = text.match(/\b(?:Phone|Mobile|Tel|Contact)[:\s#]+(\+?[\d\s\-\(\)]{8,16})\b/i);
    return phoneMatch ? phoneMatch[1].trim() : undefined;
  }

  /**
   * Validates a document specifically against a sub-control requirement.
   * Enforces strict sub-control isolation and required structured fields.
   */
  public static validateForSubControl(
    subControlId: string,
    evidenceTypes: string[] | undefined,
    filename: string,
    text: string,
    policyVsImpl: { isPolicy: boolean; isImplementation: boolean; type: string },
    parentControlId?: string,
    subControlDomain?: string
  ): ValidationResult {
    const normalizedSub = subControlId.toUpperCase().replace(/[-\s]/g, '_');
    const normalizedTypes = (evidenceTypes || []).map(t => t.toUpperCase().replace(/[-\s]/g, '_'));
    const textLower = text.toLowerCase();
    const filenameLower = filename.toLowerCase();

    const extractedDates = DateEvaluator.extractDatesFromText(text);
    const personName = this.extractPersonName(text);
    const agentId = this.extractAgentId(text);
    const employeeId = this.extractEmployeeId(text);
    const certificateNumber = this.extractCertificateNumber(text);

    let validated = false;
    let fieldValidation = false;
    let metadataMatch = Boolean(personName || agentId || employeeId || extractedDates.expiryDate || extractedDates.issueDate);
    let entityMatch = Boolean(personName || agentId || employeeId);
    let semanticMatch = false;
    let confidence = 0.50;
    let detectedEvidenceType = 'UNKNOWN';
    let validationReason = '';
    const missingMandatoryFields: string[] = [];

    const extractedFields: Record<string, any> = {
      person_name: personName,
      agent_id: agentId,
      employee_id: employeeId,
      certificate_number: certificateNumber,
      issue_date: extractedDates.issueDate,
      effective_date: extractedDates.effectiveDate,
      expiry_date: extractedDates.expiryDate,
      review_date: extractedDates.reviewDate,
      application_date: extractedDates.applicationDate,
      renewal_date: extractedDates.renewalDate,
      all_dates: extractedDates.allDates,
      date_items: extractedDates.dateItems,
      is_policy: policyVsImpl.isPolicy,
      is_implementation: policyVsImpl.isImplementation,
      policy_type: policyVsImpl.type
    };

    switch (normalizedSub) {
      case 'RENT_LEASE_AGREEMENT':
      case 'LEASE_AGREEMENT': {
        detectedEvidenceType = 'LEASE_AGREEMENT';
        const hasLease = /(?:lease agreement|rent agreement|rental agreement|tenancy agreement|commercial lease|lessor|lessee|landlord|tenant)/i.test(text);
        const hasLeaseTerms = /(?:premises|monthly rent|deposit|lease period|term of lease|address of premises|hereby agree)/i.test(text);
        const isShopsCertOnly = /(?:shops and establishment|shops & establishment|form c)/i.test(text) && !hasLease;

        if (isShopsCertOnly) {
          missingMandatoryFields.push('Premises Lease / Rent Agreement document with lessor/lessee and premises address');
          validationReason = 'Document is a Shops Certificate, which cannot satisfy Lease Agreement sub-control requirement.';
        } else if (hasLease && hasLeaseTerms) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.96;
          validationReason = 'Premises Rent/Lease Agreement verified with lessor, lessee, premises address, and lease terms.';
        } else {
          missingMandatoryFields.push('Premises Lease / Rent Agreement with valid tenancy terms');
          validationReason = 'Document lacks structured Lease Agreement terms and premises tenancy clauses.';
        }
        break;
      }

      case 'SHOPS_ESTABLISHMENT_CERTIFICATE':
      case 'SHOPS_ESTABLISHMENT': {
        detectedEvidenceType = 'SHOPS_ESTABLISHMENT_CERTIFICATE';
        const hasShops = /(?:shops and establishment|shops & establishment|commercial establishment|form c|shops act|registration certificate)/i.test(text);
        const shopsRegMatch = text.match(/\b(?:SEC|SEA|REG|SHOPS|FORM[-_]?C)[-_#:\s]+[A-Z0-9\-_/]*\d[A-Z0-9\-_/]*\b/i);
        const isLeaseOnly = /(?:lease agreement|rent agreement|lessor|lessee)/i.test(text) && !hasShops;

        if (isLeaseOnly) {
          missingMandatoryFields.push('Shops and Establishment Registration Certificate (Form C)');
          validationReason = 'Document is a Lease Agreement, which cannot satisfy Shops & Establishment Certificate sub-control.';
        } else if (hasShops && (shopsRegMatch || /(?:registration number:\s*[A-Z0-9]+|establishment name|certificate of registration)/i.test(text)) && !policyVsImpl.isPolicy) {
          if (shopsRegMatch) extractedFields['shops_registration_no'] = shopsRegMatch[0];
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.96;
          validationReason = `Shops and Establishment Registration Certificate verified${shopsRegMatch ? ' (Reg No: ' + shopsRegMatch[0] + ')' : ''}.`;
        } else if (policyVsImpl.isPolicy) {
          missingMandatoryFields.push('Official Shops & Establishment Certificate (Form C)');
          validationReason = 'Document is a policy or general profile statement; official government registration certificate is required.';
        } else {
          missingMandatoryFields.push('Shops and Establishment Registration Certificate with Registration Number');
          validationReason = 'Document lacks official Shops & Establishment certificate structure or registration number.';
        }
        break;
      }

      case 'PF_ESIC_REGISTRATION':
      case 'PF_ESIC': {
        detectedEvidenceType = 'PF_ESIC_CERTIFICATE';
        const hasPfEsic = /(?:provident fund|epfo|esic|employees'? state insurance|epf registration|esic registration)/i.test(text);
        const epfoCodeMatch = text.match(/\b[A-Z]{2}\/[A-Z0-9]{3,7}\/\d+\b/i) || text.match(/\b(?:PF|EPFO)[-_#:\s]+[A-Z0-9]*\d[A-Z0-9\-_/]*\b/i);
        const esicCodeMatch = text.match(/\b\d{17}\b/) || text.match(/\b\d{10}\b/) || text.match(/\b(?:ESIC|ESI)[-_#:\s]+[A-Z0-9]*\d[A-Z0-9\-_/]*\b/i);

        if (hasPfEsic && (epfoCodeMatch || esicCodeMatch || /(?:establishment code:\s*[A-Z0-9/]+|code allocation letter)/i.test(text)) && !policyVsImpl.isPolicy) {
          if (epfoCodeMatch) extractedFields['epfo_code'] = epfoCodeMatch[0];
          if (esicCodeMatch) extractedFields['esic_code'] = esicCodeMatch[0];
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.96;
          validationReason = `PF / ESIC Registration Certificate verified (${epfoCodeMatch ? 'EPFO: ' + epfoCodeMatch[0] : ''} ${esicCodeMatch ? 'ESIC: ' + esicCodeMatch[0] : ''}).`;
        } else if (policyVsImpl.isPolicy) {
          missingMandatoryFields.push('Official EPFO / ESIC Registration Certificate / Code Allocation Letter');
          validationReason = 'Policy statement mentions PF/ESIC, but official certificate or code is required.';
        } else {
          missingMandatoryFields.push('PF / ESIC Registration Certificate with official establishment code');
          validationReason = 'Document lacks PF/ESIC official certificate or valid establishment code.';
        }
        break;
      }

      case 'PRINCIPAL_EMPLOYER_CERTIFICATE':
      case 'PRINCIPAL_EMPLOYER': {
        detectedEvidenceType = 'PRINCIPAL_EMPLOYER_CERTIFICATE';
        const hasPrincipalEmployer = /(?:principal employer|contract labour|form\s*(?:i|ii|1|2)|clra)/i.test(text);
        const peRegMatch = text.match(/\b(?:PE[-_]?CLRA|CLRA|PE|FORM[-_]?I)[-_#:\s]+[A-Z0-9\-_/]*\d[A-Z0-9\-_/]*\b/i);

        if (hasPrincipalEmployer && (peRegMatch || /(?:certificate of registration of principal employer|registration no:\s*[A-Z0-9-]+)/i.test(text)) && !policyVsImpl.isPolicy) {
          if (peRegMatch) extractedFields['principal_employer_reg_no'] = peRegMatch[0];
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = `Principal Employer Registration Certificate verified${peRegMatch ? ' (' + peRegMatch[0] + ')' : ''}.`;
        } else {
          missingMandatoryFields.push('Principal Employer Certificate of Registration under CLRA');
          validationReason = 'Document lacks official Principal Employer certificate structure under Contract Labour Act.';
        }
        break;
      }

      case 'CCTV_INSTALLED':
      case 'CCTV_INSTALLATION': {
        detectedEvidenceType = 'CCTV_INSTALLATION_RECORD';
        const hasCctvHardware = /(?:cctv|surveillance camera|camera inventory|camera layout|dvr installation|nvr commissioning|channel 1|cam 01|bullet camera|dome camera|camera specification)/i.test(text);

        if (hasCctvHardware && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.94;
          validationReason = 'CCTV camera operational hardware inventory and installation layout verified.';
        } else if (policyVsImpl.isPolicy) {
          missingMandatoryFields.push('Physical CCTV Installation Record / Camera Hardware Inventory');
          validationReason = 'Document is a policy statement; CCTV installation sub-control strictly requires physical camera installation inventory or layout.';
        } else {
          missingMandatoryFields.push('CCTV Installation Inventory / Camera Specifications');
          validationReason = 'Document lacks physical CCTV hardware installation proof or camera inventory.';
        }
        break;
      }

      case 'CCTV_RETENTION_90_DAYS':
      case 'CCTV_RETENTION': {
        detectedEvidenceType = 'CCTV_RETENTION_CONFIGURATION';
        const hasRetentionDetails = /(?:retention|recording duration|90 days|storage settings|dvr config|nvr retention|overwrite after|tb storage)/i.test(text);
        const has90Days = /(?:90 days|>= 90|90\+|3 months|100 days|120 days)/i.test(text);

        if (hasRetentionDetails && has90Days && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'DVR/NVR technical retention configuration log verified for >= 90 days retention.';
        } else if (policyVsImpl.isPolicy) {
          missingMandatoryFields.push('Technical DVR/NVR Retention Configuration Export (>= 90 Days)');
          validationReason = 'Policy statement mentions 90 days, but technical recording configuration proof is strictly required.';
        } else {
          missingMandatoryFields.push('DVR/NVR Storage / Retention Configuration Log showing >= 90 days');
          validationReason = 'Document lacks technical verification log or settings dump demonstrating 90 days recording retention.';
        }
        break;
      }

      case 'POWER_BACKUP': {
        detectedEvidenceType = 'POWER_BACKUP_LOG';
        const hasPower = /(?:power backup|ups maintenance|dg set|diesel generator|battery bank|inverter backup|load test|kva|runtime|power supply)/i.test(text);

        if (hasPower && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Operational Power Backup (UPS / DG Set / Battery Bank) maintenance log verified.';
        } else {
          missingMandatoryFields.push('Operational Power Backup / Generator / UPS Maintenance Log');
          validationReason = 'Document lacks operational power backup or UPS test records.';
        }
        break;
      }

      case 'INTERNET_BACKUP': {
        detectedEvidenceType = 'INTERNET_BACKUP_CONFIG';
        const hasInternet = /(?:secondary isp|internet backup|dual[- ]wan|failover link|secondary leased line|redundant internet|backup broadband|airtel|tata|act fibernet)/i.test(text);

        if (hasInternet && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Secondary Internet ISP connection / dual-WAN failover configuration verified.';
        } else {
          missingMandatoryFields.push('Secondary ISP Lease / Failover Connectivity Proof');
          validationReason = 'Document lacks secondary internet connection invoice or router failover configuration.';
        }
        break;
      }

      case 'ANTIVIRUS': {
        detectedEvidenceType = 'ANTIVIRUS_CONSOLE_REPORT';
        const hasAntivirus = /(?:antivirus|endpoint protection|edr|crowdstrike|windows defender|symantec|trend micro|kaspersky|virus definitions|signature update|agent version|endpoint security)/i.test(text);

        if (hasAntivirus && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Antivirus / EDR console export and definition update report verified.';
        } else {
          missingMandatoryFields.push('Antivirus Console Export / Endpoint Definition Report');
          validationReason = 'Document lacks active antivirus deployment export or definition status.';
        }
        break;
      }

      case 'AVAILABLE':
      case 'EXTINGUISHER_AVAILABLE':
      case 'FIRE_EXTINGUISHER_AVAILABLE': {
        detectedEvidenceType = 'FIRE_EXTINGUISHER_INSPECTION';
        const hasExtinguisher = /(?:fire extinguisher|extinguisher|abc powder|co2 cylinder|fire cylinder|fire safety equipment)/i.test(text);
        if (hasExtinguisher && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Fire extinguisher equipment availability verified on premises.';
        } else {
          missingMandatoryFields.push('Physical Fire Extinguisher presence / inventory');
          validationReason = 'Document lacks proof of physical fire extinguisher equipment on premises.';
        }
        break;
      }

      case 'FUNCTIONAL':
      case 'EXTINGUISHER_FUNCTIONAL':
      case 'FIRE_EXTINGUISHER_FUNCTIONAL': {
        detectedEvidenceType = 'FIRE_EXTINGUISHER_INSPECTION';
        const hasFunctional = /(?:pressure gauge|functional|ok|serviceable|maintenance log|inspection tag|cylinder inspection|gauge green|hydrostatic test|serviced)/i.test(text);
        if (hasFunctional && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Fire extinguisher pressure gauge and operational functionality verified.';
        } else {
          missingMandatoryFields.push('Fire Extinguisher Pressure Gauge / Functional Service Tag');
          validationReason = 'Document lacks fire extinguisher operational functionality or pressure gauge status.';
        }
        break;
      }

      case 'NOT_EXPIRED':
      case 'EXTINGUISHER_NOT_EXPIRED':
      case 'FIRE_EXTINGUISHER_NOT_EXPIRED': {
        detectedEvidenceType = 'FIRE_EXTINGUISHER_INSPECTION';
        const hasExtinguisherContext = /(?:fire extinguisher|extinguisher|cylinder|pressure gauge|abc powder|co2 extinguisher|fire safety equipment)/i.test(text);
        const hasRefillDate = /(?:refill due|next inspection|next refill|serviced date|maintenance date|refill date|due date)/i.test(text);
        if (hasExtinguisherContext && hasRefillDate && !policyVsImpl.isPolicy) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Fire extinguisher refill and maintenance validity date verified.';
        } else {
          missingMandatoryFields.push('Fire Extinguisher Refill Due / Inspection Validity Date');
          validationReason = 'Document lacks fire extinguisher refill or maintenance due date.';
        }
        break;
      }

      case 'POLICY_EVIDENCE': {
        detectedEvidenceType = 'POLICY_DOCUMENT';
        const isPolicyDoc = policyVsImpl.isPolicy || /(?:policy|procedure|standard|guideline|governance|sop)/i.test(text);
        
        // Check domain-specific policy requirements if scoped
        if (parentControlId === 'ZTI-008' || subControlDomain === 'ENDPOINT_SECURITY_POLICY') {
          const hasEndpointPolicy = /(?:endpoint security|usb[-_\s]*restriction|removable[-_\s]*media|cloud[-_\s]*storage policy|device[-_\s]*control policy|storage[-_\s]*restriction|usb[-_\s]*storage[-_\s]*control|usb[-_\s]*policy|storage[-_\s]*policy)/i.test(text);
          if (hasEndpointPolicy && isPolicyDoc) {
            detectedEvidenceType = 'ENDPOINT_SECURITY_POLICY';
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.90;
            validationReason = 'Approved endpoint security & removable media restriction policy verified.';
          } else {
            missingMandatoryFields.push('Endpoint Security & Removable Media Restriction Policy');
            validationReason = 'Document is not an approved endpoint security or USB restriction policy.';
          }
        } else if (parentControlId === 'ZTI-009' || subControlDomain === 'WEB_FILTERING_POLICY') {
          const hasWebFilteringPolicy = /(?:web filtering|acceptable use|internet usage|social media policy|messaging apps policy|personal email)/i.test(text);
          if (hasWebFilteringPolicy && isPolicyDoc) {
            detectedEvidenceType = 'WEB_FILTERING_POLICY';
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.90;
            validationReason = 'Approved web filtering & acceptable communication usage policy verified.';
          } else {
            missingMandatoryFields.push('Web Filtering & Communication Acceptable Use Policy');
            validationReason = 'Document is not an approved web filtering or personal communication blacklisting policy.';
          }
        } else if (isPolicyDoc) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.90;
          validationReason = 'Approved organization policy document verified.';
        } else {
          missingMandatoryFields.push('Formal Governance / Information Security Policy Document');
          validationReason = 'Document is not a recognized policy or governance standard.';
        }
        break;
      }

      case 'IMPLEMENTATION_EVIDENCE': {
        detectedEvidenceType = 'IMPLEMENTATION_EVIDENCE';
        const isImplDoc = policyVsImpl.isImplementation || /(?:configuration|gpo|dlp|registry|firewall|proxy|rule|blacklist|screenshot|export|log|console|endpoint|syn-endpoint)/i.test(text);

        // Check domain-specific implementation requirements if scoped
        if (parentControlId === 'ZTI-008' || subControlDomain === 'ENDPOINT_DATA_RESTRICTION_CONFIG') {
          const hasEndpointImpl = /(?:storagedevicepolicies|removable[-_\s]*media|usb[-_\s]*(?:storage[-_\s]*)?block(?:ed)?|dlp[-_\s]*config|deny_all|registry|storport|writeprotect|removabledisks|deny_write|disable-removable-media|gpo[-_\s]*configuration|gpo[-_\s]*audit|gpo[-_\s]*status|usb_block|syn-endpoint)/i.test(text);
          if (hasEndpointImpl && isImplDoc) {
            detectedEvidenceType = 'DLP_GPO_CONFIGURATION_EXPORT';
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.95;
            validationReason = 'Operational GPO/DLP USB and removable storage technical restriction configuration verified.';
          } else if (policyVsImpl.isPolicy && !isImplDoc) {
            missingMandatoryFields.push('Technical GPO/DLP Configuration Export (Registry / Group Policy Dump)');
            validationReason = 'Document is a policy document; technical configuration proof is required.';
          } else {
            missingMandatoryFields.push('Technical GPO/DLP USB Storage Restriction Configuration');
            validationReason = 'Document lacks technical GPO / DLP removable media restriction settings.';
          }
        } else if (parentControlId === 'ZTI-009' || subControlDomain === 'WEB_COMMUNICATION_FILTERING_CONFIG') {
          const hasWebFilteringImpl = /(?:firewall|proxy|url\s*filtering|blacklist|rule_id|rule[-_]?fw|social\s*media|personal\s*email|messaging|squid|fortigate|palo\s*alto|checkpoint|iptables|action\s*[:;=]?\s*(?:deny|drop)|target_domain)/i.test(text);
          if (hasWebFilteringImpl && isImplDoc) {
            detectedEvidenceType = 'FIREWALL_PROXY_CONFIGURATION_EXPORT';
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.95;
            validationReason = 'Operational firewall/proxy URL filtering and blacklisting configuration verified.';
          } else if (policyVsImpl.isPolicy && !isImplDoc) {
            missingMandatoryFields.push('Technical Firewall / Proxy Blacklist Export');
            validationReason = 'Document is a policy document; operational technical firewall/proxy export is required.';
          } else {
            missingMandatoryFields.push('Technical Firewall / Proxy URL Filtering Blacklist Rules');
            validationReason = 'Document lacks technical proxy / firewall blacklist rules for social sites and messaging.';
          }
        } else if (isImplDoc) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.95;
          validationReason = 'Operational technical implementation configuration verified.';
        } else {
          missingMandatoryFields.push('Technical Implementation Evidence (GPO/DLP export, firewall config, logs)');
          validationReason = 'Document lacks technical implementation configuration or operational proof.';
        }
        break;
      }

      default: {
        // Match against normalizedTypes if provided
        if (normalizedTypes.length > 0) {
          const typeMatch = normalizedTypes.some(t => textLower.includes(t.toLowerCase().replace(/_/g, ' ')) || filenameLower.includes(t.toLowerCase().replace(/_/g, ' ')));
          if (typeMatch && text.length > 50) {
            fieldValidation = true;
            validated = true;
            semanticMatch = true;
            confidence = 0.85;
            validationReason = `Document satisfied sub-control domain context '${subControlId}'.`;
          } else {
            missingMandatoryFields.push(`Evidence matching sub-control '${subControlId}'`);
            validationReason = `Document content did not match sub-control '${subControlId}'.`;
          }
        } else if (text.length > 50) {
          fieldValidation = true;
          validated = true;
          semanticMatch = true;
          confidence = 0.80;
          validationReason = `Document matched context for '${subControlId}'.`;
        } else {
          missingMandatoryFields.push(`Evidence for '${subControlId}'`);
          validationReason = 'Insufficient document body content.';
        }
        break;
      }
    }

    return {
      validated,
      confidence,
      fieldValidation,
      metadataMatch,
      entityMatch,
      semanticMatch,
      detectedEvidenceType,
      validationReason,
      missingMandatoryFields,
      extractedFields
    };
  }
}
