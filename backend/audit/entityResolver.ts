import crypto from 'node:crypto';
import {
  AuditEntity,
  AuditEntityFinding,
  AuditParameter,
  AuditParameterResult,
  AuditSessionEntityResolutionResult,
  EntityConflict,
  EntityEvidenceReference,
  EvidenceItem
} from './models.js';

export interface RawIdentitySignal {
  rawName?: string;
  normalizedName: string;
  displayName: string;
  agentId?: string | null;
  canonicalAgentId?: string | null;
  employeeId?: string | null;
  canonicalEmployeeId?: string | null;
  certificateNumber?: string | null;
  canonicalCertNumber?: string | null;
  email?: string | null;
  phone?: string | null;
  agencyId?: string | null;
  parameterId: string;
  parameterTitle?: string;
  fileId: string;
  filename: string;
  evidenceId: string;
  confidence: number;
  extractedFields: Record<string, any>;
}

export class EntityResolver {
  /**
   * Main entry point for audit-session-level entity correlation.
   * Runs AFTER all parameter results and evidence have been collected.
   */
  public static resolveAuditSessionEntities(
    parameterResults: AuditParameterResult[],
    auditSessionId?: string
  ): AuditSessionEntityResolutionResult {
    // 1. Collect all VALIDATED evidence items across all parameters
    const validatedItems = this.collectValidatedEvidence(parameterResults);

    // 2. Extract identity signals from each validated evidence item
    const signals: RawIdentitySignal[] = [];
    for (const item of validatedItems) {
      const sig = this.extractIdentitySignal(item.evidence, item.parameter);
      if (sig) {
        signals.push(sig);
      }
    }

    // 3. Cluster and match signals into unique entities
    const entities = this.clusterEntities(signals, auditSessionId);

    // 4. Detect entity conflicts across and within clusters
    const { conflicts, entityFindings } = this.detectEntityConflicts(entities);

    const consistentCount = entities.filter(e => e.status === 'CONSISTENT').length;
    const reviewCount = entities.filter(e => e.status === 'REVIEW').length;

    const result: AuditSessionEntityResolutionResult = {
      entities,
      conflicts,
      entityFindings,
      summary: {
        totalEntities: entities.length,
        consistentCount,
        reviewCount,
        total_entities: entities.length,
        consistent_count: consistentCount,
        review_count: reviewCount
      },
      entity_findings: entityFindings
    };

    return result;
  }

  /**
   * Filters and collects ONLY validated evidence items from parameter results.
   * Rejects unvalidated candidates, filename-only matches, and rejected evidence.
   */
  public static collectValidatedEvidence(
    parameterResults: AuditParameterResult[]
  ): Array<{ parameter: AuditParameter; evidence: EvidenceItem }> {
    const validatedList: Array<{ parameter: AuditParameter; evidence: EvidenceItem }> = [];

    for (const paramResult of parameterResults) {
      if (!paramResult.evidence || paramResult.evidence.length === 0) continue;

      for (const evidence of paramResult.evidence) {
        // STRICT EVIDENCE HARDENING GATE:
        // Must be validated and not filename-only
        const isFilenameOnly = Boolean(
          evidence.is_filename_only ||
          evidence.isFilenameOnly ||
          evidence.extracted_fields?.is_filename_only ||
          evidence.extracted_fields?.isFilenameOnly
        );

        const isValidated = evidence.validated !== false &&
          evidence.extracted_fields?.validated !== false &&
          !isFilenameOnly;

        if (isValidated) {
          validatedList.push({
            parameter: paramResult.parameter,
            evidence
          });
        }
      }
    }

    return validatedList;
  }

  /**
   * Extracts person names and identity identifiers from validated evidence.
   */
  public static extractIdentitySignal(
    evidence: EvidenceItem,
    parameter: AuditParameter
  ): RawIdentitySignal | null {
    const fields = evidence.extracted_fields || {};
    const textSnippet = (evidence.snippet || '') + ' ' + (evidence.filename || '');

    // 1. Extract Person Name
    let rawName: string | undefined = fields.person_name || fields.name || fields.agent_name || fields.employee_name;
    if (!rawName) {
      const nameMatch = textSnippet.match(/(?:Employee(?:\s*Name)?|Agent(?:\s*(?:\/|\&)\s*Employee)?(?:\s*Name)?|Staff(?:\s*Name)?|Candidate(?:\s*Name)?|Participant(?:\s*Name)?|Director|VP|Name|User|Officer|Person|To certify that)[:,\s]+([A-Za-z\.\'\- ]{2,35})(?=[\r\n]|$)/i);
      if (nameMatch) {
        const candidate = nameMatch[1].trim();
        if (candidate.length >= 2 && !/(?:status|passed|completed|policy|procedure|training|date|active|valid)/i.test(candidate)) {
          rawName = candidate;
        }
      }
    }

    // 2. Extract Agent ID
    let agentId: string | null = fields.agent_id || fields.agentId || fields.staff_id || null;
    if (!agentId) {
      const agMatch = textSnippet.match(/\b(?:Agent\s*(?:ID|Code|#|Num|Number)|Agent\s*No|Agent\s*#)[:\s#]+([A-Z0-9\-_]{2,20})\b/i) ||
        textSnippet.match(/\bAgent[:\s#]+(?!Name\b)([A-Z0-9\-_]{2,20})\b/i) ||
        textSnippet.match(/\b(AG[-_]?\d{2,10})\b/i);
      if (agMatch) {
        agentId = agMatch[1];
      }
    }

    // 3. Extract Employee ID
    let employeeId: string | null = fields.employee_id || fields.employeeId || fields.emp_id || null;
    if (!employeeId) {
      const empMatch = textSnippet.match(/\b(?:Employee\s*(?:ID|Code|#|Num|Number)?|Emp\s*(?:ID|Code|#)?|Staff\s*ID)[:\s#]+([A-Z0-9\-_]{2,20})\b/i) ||
        textSnippet.match(/\b(EMP[-_]?\d{2,10})\b/i);
      if (empMatch) {
        employeeId = empMatch[1];
      }
    }

    // 4. Extract Certificate Number
    let certificateNumber: string | null = fields.certificate_number || fields.certificate_no || fields.dra_certificate_no || fields.acknowledgement_number || null;
    if (!certificateNumber) {
      const certMatch = textSnippet.match(/\b(?:Certificate\s*(?:No|Number|#|Id)?|DRA\s*(?:No|Number|#)?|Acknowledgement\s*(?:Slip\s*)?(?:No|Number|#)?|Ack\s*(?:No|Number|#)?)[:\s#]+([A-Z0-9\-_/]{3,30})\b/i) ||
        textSnippet.match(/\b((?:DRA|PV-ACK|CERT|NBFET|PCC)[-_#:\s][A-Z0-9\-_/]{3,25})\b/i);
      if (certMatch) {
        certificateNumber = certMatch[1];
      }
    }

    // 5. Extract Email & Phone
    let email: string | null = fields.email || null;
    if (!email) {
      const emailMatch = textSnippet.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
      if (emailMatch) email = emailMatch[0];
    }

    let phone: string | null = fields.phone || fields.mobile || null;
    if (!phone) {
      const phoneMatch = textSnippet.match(/\b(?:Phone|Mobile|Tel|Contact)[:\s#]+(\+?[\d\s\-\(\)]{8,16})\b/i);
      if (phoneMatch) phone = phoneMatch[1].trim();
    }

    // If neither name nor strong identifier was found, this document does not refer to a person entity
    if (!rawName && !agentId && !employeeId && !certificateNumber) {
      return null;
    }

    const normalizedName = this.normalizeName(rawName || '');
    const displayName = rawName ? this.cleanDisplayName(rawName) : (agentId ? `Agent ${agentId}` : 'Unknown Entity');

    return {
      rawName,
      normalizedName,
      displayName,
      agentId: this.normalizeIdentifier(agentId),
      canonicalAgentId: this.canonicalIdentifier(agentId),
      employeeId: this.normalizeIdentifier(employeeId),
      canonicalEmployeeId: this.canonicalIdentifier(employeeId),
      certificateNumber: this.normalizeIdentifier(certificateNumber),
      canonicalCertNumber: this.canonicalIdentifier(certificateNumber),
      email: email ? email.toLowerCase().trim() : null,
      phone: phone ? phone.replace(/\s+/g, '') : null,
      agencyId: fields.agency_id ? this.normalizeIdentifier(fields.agency_id) : null,
      parameterId: parameter.id,
      parameterTitle: parameter.parameter,
      fileId: evidence.file_id,
      filename: evidence.filename,
      evidenceId: evidence.evidence_id,
      confidence: evidence.confidence || 0.90,
      extractedFields: fields
    };
  }

  /**
   * Normalizes human names to resolve harmless variations (casing, punctuation, initials).
   * E.g. "John Smith", "JOHN SMITH", "John  Smith", "John A. Smith", "John A Smith"
   */
  public static normalizeName(name: string): string {
    if (!name) return '';
    let norm = name.toLowerCase().trim();
    // Remove honorific titles/prefixes at start
    norm = norm.replace(/^(?:mr|mrs|ms|dr|prof|shri|smt)\.?\s+/i, '');
    // Remove periods from middle initials (e.g. "a." -> "a")
    norm = norm.replace(/\b([a-z])\./gi, '$1');
    // Remove punctuation except letters and spaces
    norm = norm.replace(/[^\p{L}\p{N}\s\-]/gu, '');
    // Collapse whitespace
    norm = norm.replace(/\s+/g, ' ').trim();
    return norm;
  }

  /**
   * Standardizes display name capitalization for pristine UI rendering.
   */
  public static cleanDisplayName(name: string): string {
    if (!name) return '';
    const cleaned = name.trim().replace(/\s+/g, ' ');
    // Title Case
    return cleaned.replace(/\b\w+/g, word => {
      // If all caps middle initial or abbreviation
      if (word.length === 1) return word.toUpperCase();
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    });
  }

  /**
   * Normalizes identifiers (Agent ID, Employee ID).
   */
  public static normalizeIdentifier(id?: string | null): string | null {
    if (!id) return null;
    const trimmed = id.trim().toUpperCase();
    return trimmed.replace(/\s+/g, '-');
  }

  /**
   * Canonical alphanumeric identifier key for strict comparison (e.g. "AG-123" -> "AG123").
   */
  public static canonicalIdentifier(id?: string | null): string | null {
    if (!id) return null;
    return id.toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  /**
   * Calculates Levenshtein Distance between two strings.
   */
  public static levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Computes normalized similarity between 0.0 and 1.0.
   */
  public static nameSimilarity(nameA: string, nameB: string): number {
    const normA = this.normalizeName(nameA);
    const normB = this.normalizeName(nameB);
    if (!normA || !normB) return 0;
    if (normA === normB) return 1.0;

    const maxLen = Math.max(normA.length, normB.length);
    if (maxLen === 0) return 1.0;

    const dist = this.levenshteinDistance(normA, normB);
    return 1 - dist / maxLen;
  }

  /**
   * Clusters identity signals into distinct AuditEntity instances.
   * Priority: STRONG IDENTIFIERS > EXACT NAME > FUZZY NAME
   */
  public static clusterEntities(
    signals: RawIdentitySignal[],
    auditSessionId?: string
  ): AuditEntity[] {
    const clusters: Array<{
      signals: RawIdentitySignal[];
      matchingReasons: string[];
      canonicalAgentId?: string | null;
      canonicalEmployeeId?: string | null;
      canonicalCertNumber?: string | null;
      email?: string | null;
      phone?: string | null;
      normalizedName?: string;
    }> = [];

    // Helper: Find matching cluster for a signal
    const findClusterIndex = (sig: RawIdentitySignal): number => {
      // 1. Strong Identifier Matching (Highest Priority)
      if (sig.canonicalAgentId) {
        const idx = clusters.findIndex(c => c.canonicalAgentId === sig.canonicalAgentId);
        if (idx !== -1) return idx;
      }

      if (sig.canonicalEmployeeId) {
        const idx = clusters.findIndex(c => c.canonicalEmployeeId === sig.canonicalEmployeeId);
        if (idx !== -1) return idx;
      }

      if (sig.canonicalCertNumber) {
        const idx = clusters.findIndex(c => c.canonicalCertNumber === sig.canonicalCertNumber);
        if (idx !== -1) return idx;
      }

      if (sig.email) {
        const idx = clusters.findIndex(c => c.email === sig.email);
        if (idx !== -1) return idx;
      }

      // 2. Exact Normalized Name Matching
      // Only merge if neither entity has a conflicting strong identifier!
      if (sig.normalizedName) {
        const idx = clusters.findIndex(c => {
          if (c.normalizedName !== sig.normalizedName) return false;

          // If both have agent IDs and they differ, DO NOT merge! (Different agents with same name)
          if (sig.canonicalAgentId && c.canonicalAgentId && sig.canonicalAgentId !== c.canonicalAgentId) {
            return false;
          }
          // If both have employee IDs and they differ, DO NOT merge!
          if (sig.canonicalEmployeeId && c.canonicalEmployeeId && sig.canonicalEmployeeId !== c.canonicalEmployeeId) {
            return false;
          }
          return true;
        });

        if (idx !== -1) return idx;
      }

      return -1;
    };

    // Process all signals
    for (const sig of signals) {
      const matchIdx = findClusterIndex(sig);

      if (matchIdx !== -1) {
        const cluster = clusters[matchIdx];
        cluster.signals.push(sig);

        // Update cluster identifiers if newly discovered
        if (!cluster.canonicalAgentId && sig.canonicalAgentId) cluster.canonicalAgentId = sig.canonicalAgentId;
        if (!cluster.canonicalEmployeeId && sig.canonicalEmployeeId) cluster.canonicalEmployeeId = sig.canonicalEmployeeId;
        if (!cluster.canonicalCertNumber && sig.canonicalCertNumber) cluster.canonicalCertNumber = sig.canonicalCertNumber;
        if (!cluster.email && sig.email) cluster.email = sig.email;
        if (!cluster.phone && sig.phone) cluster.phone = sig.phone;
        if (!cluster.normalizedName && sig.normalizedName) cluster.normalizedName = sig.normalizedName;

        if (sig.canonicalAgentId && cluster.canonicalAgentId === sig.canonicalAgentId) {
          cluster.matchingReasons.push(`STRONG_IDENTIFIER_MATCH (Agent ID: ${sig.agentId})`);
        } else if (sig.canonicalEmployeeId && cluster.canonicalEmployeeId === sig.canonicalEmployeeId) {
          cluster.matchingReasons.push(`STRONG_IDENTIFIER_MATCH (Employee ID: ${sig.employeeId})`);
        } else if (sig.normalizedName && cluster.normalizedName === sig.normalizedName) {
          cluster.matchingReasons.push(`EXACT_NAME_MATCH (${sig.displayName})`);
        }
      } else {
        // Create a new cluster
        clusters.push({
          signals: [sig],
          matchingReasons: [
            sig.agentId ? `STRONG_IDENTIFIER_MATCH (Agent ID: ${sig.agentId})` : `EXACT_NAME_MATCH (${sig.displayName})`
          ],
          canonicalAgentId: sig.canonicalAgentId,
          canonicalEmployeeId: sig.canonicalEmployeeId,
          canonicalCertNumber: sig.canonicalCertNumber,
          email: sig.email,
          phone: sig.phone,
          normalizedName: sig.normalizedName
        });
      }
    }

    // Build AuditEntity objects from clusters
    const entities: AuditEntity[] = [];

    clusters.forEach((cluster, idx) => {
      const entityId = `ENTITY-${String(idx + 1).padStart(3, '0')}`;
      const primarySignal = cluster.signals[0];

      // Determine best display name
      const distinctNames = Array.from(new Set(
        cluster.signals
          .map(s => s.displayName)
          .filter((n): n is string => Boolean(n) && n !== 'Unknown Entity')
      ));

      const distinctNormalizedNames = Array.from(new Set(
        cluster.signals
          .map(s => s.normalizedName)
          .filter((n): n is string => Boolean(n))
      ));

      const primaryName = distinctNames[0] || (cluster.canonicalAgentId ? `Agent ${cluster.canonicalAgentId}` : 'Entity ' + entityId);
      const primaryNormalized = distinctNormalizedNames[0] || this.normalizeName(primaryName);

      // Extract all identifier values across cluster signals
      const agentId = cluster.signals.find(s => s.agentId)?.agentId || null;
      const employeeId = cluster.signals.find(s => s.employeeId)?.employeeId || null;
      const certificateNumber = cluster.signals.find(s => s.certificateNumber)?.certificateNumber || null;
      const email = cluster.signals.find(s => s.email)?.email || null;
      const phone = cluster.signals.find(s => s.phone)?.phone || null;
      const agencyId = cluster.signals.find(s => s.agencyId)?.agencyId || null;

      // Evidence references
      const evidenceReferences: EntityEvidenceReference[] = cluster.signals.map(s => ({
        parameterId: s.parameterId,
        parameterTitle: s.parameterTitle,
        fileId: s.fileId,
        filename: s.filename,
        evidenceId: s.evidenceId,
        confidence: s.confidence,
        extractedName: s.rawName,
        extractedAgentId: s.agentId || undefined,
        extractedEmployeeId: s.employeeId || undefined,
        extractedCertNumber: s.certificateNumber || undefined,
        extractedFields: s.extractedFields,
        // Snake case
        parameter_id: s.parameterId,
        parameter_title: s.parameterTitle,
        file_id: s.fileId,
        evidence_id: s.evidenceId,
        extracted_name: s.rawName,
        extracted_agent_id: s.agentId || undefined,
        extracted_employee_id: s.employeeId || undefined,
        extracted_cert_number: s.certificateNumber || undefined,
        extracted_fields: s.extractedFields
      }));

      // Check intra-cluster conflicts (e.g. Same Agent ID with multiple conflicting names)
      const conflicts: EntityConflict[] = [];

      if (distinctNormalizedNames.length > 1) {
        const conflictType = agentId ? 'AGENT_ID_NAME_MISMATCH' :
          (employeeId ? 'EMPLOYEE_ID_NAME_MISMATCH' : 'POSSIBLE_ENTITY_MISMATCH');

        const title = agentId
          ? `POSSIBLE ENTITY MISMATCH: Conflicting Names for Agent ID ${agentId}`
          : (employeeId
            ? `POSSIBLE ENTITY MISMATCH: Conflicting Names for Employee ID ${employeeId}`
            : `POSSIBLE ENTITY MISMATCH: Name Discrepancy in Cluster`);

        const reason = agentId
          ? `Agent ID ${agentId} is associated with conflicting names (${distinctNames.join(' vs ')}).`
          : (employeeId
            ? `Employee ID ${employeeId} is associated with conflicting names (${distinctNames.join(' vs ')}).`
            : `Multiple conflicting names (${distinctNames.join(' vs ')}) resolved to the same identifier cluster.`);

        conflicts.push({
          conflictType,
          severity: 'REVIEW',
          title,
          description: `Identity information conflict detected across audit session documentary evidence.`,
          reason,
          involvedEvidence: evidenceReferences,
          conflictingAttributes: {
            attribute: 'name',
            values: distinctNames
          },
          conflict_type: conflictType,
          involved_evidence: evidenceReferences,
          conflicting_attributes: {
            attribute: 'name',
            values: distinctNames
          }
        });
      }

      // Check if certificate numbers conflict
      const certNumbers = Array.from(new Set(
        cluster.signals
          .map(s => s.canonicalCertNumber)
          .filter((c): c is string => Boolean(c))
      ));
      if (certNumbers.length > 1 && distinctNormalizedNames.length > 1) {
        conflicts.push({
          conflictType: 'CERTIFICATE_NUMBER_MISMATCH',
          severity: 'REVIEW',
          title: `POSSIBLE ENTITY MISMATCH: Certificate Number Conflict`,
          description: `Different certificate numbers and names associated with the same identity cluster.`,
          reason: `Different certificate numbers (${certNumbers.join(', ')}) associated with conflicting names.`,
          involvedEvidence: evidenceReferences,
          conflictingAttributes: {
            attribute: 'certificate_number',
            values: certNumbers
          },
          conflict_type: 'CERTIFICATE_NUMBER_MISMATCH',
          involved_evidence: evidenceReferences,
          conflicting_attributes: {
            attribute: 'certificate_number',
            values: certNumbers
          }
        });
      }

      const status: 'CONSISTENT' | 'REVIEW' = conflicts.length > 0 ? 'REVIEW' : 'CONSISTENT';

      // Deduplicate matching signals
      const matchingSignals = Array.from(new Set(cluster.matchingReasons));

      entities.push({
        entityId,
        entityType: 'PERSON',
        displayName: primaryName,
        normalizedName: primaryNormalized,
        identifiers: {
          employeeId,
          agentId,
          certificateNumber,
          email,
          phone,
          agencyId,
          employee_id: employeeId,
          agent_id: agentId,
          certificate_number: certificateNumber,
          agency_id: agencyId
        },
        evidenceReferences,
        matchingSignals,
        confidence: conflicts.length > 0 ? 0.90 : (cluster.signals.length > 1 ? 0.98 : 0.90),
        status,
        conflicts,
        auditSessionId,
        createdAt: new Date().toISOString(),
        // Snake case aliases
        entity_id: entityId,
        entity_type: 'PERSON',
        display_name: primaryName,
        normalized_name: primaryNormalized,
        evidence_references: evidenceReferences,
        matching_signals: matchingSignals,
        audit_session_id: auditSessionId,
        created_at: new Date().toISOString()
      });
    });

    return entities;
  }

  /**
   * Compiles audit-level entity findings from detected conflicts.
   */
  public static detectEntityConflicts(
    entities: AuditEntity[]
  ): { conflicts: EntityConflict[]; entityFindings: AuditEntityFinding[] } {
    const allConflicts: EntityConflict[] = [];
    const entityFindings: AuditEntityFinding[] = [];

    let findingIdx = 1;

    for (const entity of entities) {
      if (entity.conflicts && entity.conflicts.length > 0) {
        for (const conflict of entity.conflicts) {
          allConflicts.push(conflict);

          const findingId = `FINDING-ENTITY-${String(findingIdx++).padStart(3, '0')}`;
          entityFindings.push({
            findingId,
            entityId: entity.entityId,
            title: conflict.title,
            status: 'REVIEW',
            reason: conflict.reason,
            conflictingAttributes: {
              [conflict.conflictingAttributes.attribute]: conflict.conflictingAttributes.values
            },
            evidenceReferences: conflict.involvedEvidence,
            createdAt: new Date().toISOString(),
            // Snake case
            finding_id: findingId,
            entity_id: entity.entityId,
            conflicting_attributes: {
              [conflict.conflictingAttributes.attribute]: conflict.conflictingAttributes.values
            },
            evidence_references: conflict.involvedEvidence,
            created_at: new Date().toISOString()
          });
        }
      }
    }

    return {
      conflicts: allConflicts,
      entityFindings
    };
  }
}
