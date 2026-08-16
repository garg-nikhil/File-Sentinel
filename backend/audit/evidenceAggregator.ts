import { AuditParameter, EvidenceItem, ControlEvidenceSet, AuditParameterResult, AuditParameterStatus } from './models.js';

export class EvidenceAggregator {
  public static aggregate(parameter: AuditParameter, evidenceItems: EvidenceItem[]): {
    evidenceSet: ControlEvidenceSet,
    hasContradiction: boolean,
    hasValidated: boolean
  } {
    const primaryEvidence = evidenceItems.find(e => e.validated) || null;
    const supportingEvidence: EvidenceItem[] = [];
    const reviewEvidence: EvidenceItem[] = [];
    const contradictoryEvidence: EvidenceItem[] = [];
    const rejectedCandidates: EvidenceItem[] = [];

    // Group evidence by entity to find contradictions
    const entityGroups = new Map<string, EvidenceItem[]>();

    for (const e of evidenceItems) {
      if (!e.validated && e.validation_status !== 'PARTIALLY_VALIDATED') {
        rejectedCandidates.push(e);
        continue;
      }

      const entityId = this.extractEntityId(e);

      if (!entityGroups.has(entityId)) {
        entityGroups.set(entityId, []);
      }
      entityGroups.get(entityId)!.push(e);
    }

    let hasContradiction = false;

    // Detect contradictions within each entity group
    for (const [entityId, items] of entityGroups.entries()) {
      const claims = items.map(e => ({
        item: e,
        status: this.extractStatusClaim(e)
      }));

      // Find if there are conflicting statuses
      const statuses = claims.map(c => c.status).filter(Boolean) as string[];
      const uniqueStatuses = Array.from(new Set(statuses));
      
      const isContradictory = uniqueStatuses.length > 1 && this.areStatusesContradictory(uniqueStatuses);
      
      if (isContradictory) {
        hasContradiction = true;
        for (const c of claims) {
          c.item.classification = 'CONTRADICTORY';
          contradictoryEvidence.push(c.item);
        }
      } else {
        for (const c of claims) {
          if (c.item === primaryEvidence) {
            c.item.classification = 'VALIDATED';
          } else if (c.item.validated) {
            c.item.classification = 'VALIDATED';
            supportingEvidence.push(c.item);
          } else {
            c.item.classification = 'PARTIALLY_VALIDATED';
            reviewEvidence.push(c.item);
          }
        }
      }
    }

    const evidenceSet: ControlEvidenceSet = {
      controlId: parameter.id,
      primaryEvidence: primaryEvidence?.classification !== 'CONTRADICTORY' ? primaryEvidence : null,
      supportingEvidence,
      reviewEvidence,
      contradictoryEvidence,
      rejectedCandidates
    };

    if (evidenceSet.primaryEvidence === null && supportingEvidence.length > 0) {
       evidenceSet.primaryEvidence = supportingEvidence.shift() || null;
    }

    return {
      evidenceSet,
      hasContradiction,
      hasValidated: evidenceSet.primaryEvidence !== null || evidenceSet.supportingEvidence.length > 0
    };
  }

  public static extractEntityId(e: EvidenceItem): string {
    const ef = e.extracted_fields || {};
    const sf = e.structured_fields || {};
    
    // Explicit structured fields
    if (ef.gstin || sf.gstin) return `GSTIN:${ef.gstin || sf.gstin}`;
    if (ef.pan || sf.pan) return `PAN:${ef.pan || sf.pan}`;
    if (ef.employee_id || sf.employee_id) return `EMP:${ef.employee_id || sf.employee_id}`;
    if (ef.agent_id || sf.agent_id) return `AGENT:${ef.agent_id || sf.agent_id}`;
    if (ef.certificate_number || sf.certificate_number) return `CERT:${ef.certificate_number || sf.certificate_number}`;
    if (ef.policy_number || sf.policy_number) return `POLICY:${ef.policy_number || sf.policy_number}`;
    if (ef.shops_registration_no || sf.shops_registration_no) return `SHOPS:${ef.shops_registration_no || sf.shops_registration_no}`;
    if (ef.endpoint_id || sf.endpoint_id) return `ENDPOINT:${ef.endpoint_id || sf.endpoint_id}`;
    if (ef.hostname || sf.hostname) return `HOST:${ef.hostname || sf.hostname}`;
    if (ef.person_name || sf.person_name) return `PERSON:${(ef.person_name || sf.person_name).toLowerCase().trim()}`;
    if (ef.entity_name || sf.entity_name) return `ENTITY:${(ef.entity_name || sf.entity_name).toLowerCase().trim()}`;

    // Extract from text / snippet / raw_text
    const text = ((ef.raw_text || '') + ' ' + (e.snippet || '') + ' ' + (e.filename || '')).trim();
    
    // Check for specific endpoint / machine identifier pattern (e.g., WS-99, PC-01, E1, HOST-01)
    const codeMatch = text.match(/\b(WS-\d+|PC-\d+|HOST-[A-Za-z0-9]+|E\d+|EP-\d+)\b/i);
    if (codeMatch) {
      return `ENDPOINT:${codeMatch[1].toUpperCase()}`;
    }

    // Check for named entity in header/content
    const entityMatch = text.match(/(?:Entity|Agency|Company|Vendor|Establishment)\s*[:=]\s*([A-Za-z0-9\s.,&-]{3,40})(?=[\r\n]|$)/i);
    if (entityMatch) {
      return `ENTITY:${entityMatch[1].toLowerCase().trim()}`;
    }

    return 'GLOBAL';
  }

  public static extractStatusClaim(e: EvidenceItem): string | null {
    const ef = e.extracted_fields || {};
    const sf = e.structured_fields || {};
    const text = ((ef.raw_text || '') + ' ' + (e.snippet || '')).toUpperCase();
    
    // Check structured fields first
    const statusVal = (ef.status || sf.status || ef.usb_storage || sf.usb_storage || ef.gpo_status || sf.gpo_status || '').toUpperCase();
    if (statusVal === 'BLOCKED' || statusVal === 'DENIED' || statusVal === 'RESTRICTED') return 'BLOCKED';
    if (statusVal === 'ALLOWED' || statusVal === 'PERMITTED' || statusVal === 'ENABLED') return 'ALLOWED';
    if (statusVal === 'APPLIED') return 'APPLIED';
    if (statusVal === 'NOT_APPLIED' || statusVal === 'DISABLED') return 'NOT_APPLIED';
    if (statusVal === 'ACTIVE' || statusVal === 'VALID') return 'ACTIVE';
    if (statusVal === 'TERMINATED' || statusVal === 'CANCELLED' || statusVal === 'REVOKED') return 'TERMINATED';
    if (statusVal === 'EXPIRED') return 'EXPIRED';

    // Look for key-value claims in text
    if (/\bBLOCKED\b/.test(text) || /\bDENY\b/.test(text) || /USB_STORAGE\s*[:=,]\s*BLOCKED/i.test(text)) return 'BLOCKED';
    if (/\bALLOWED\b/.test(text) || /\bALLOW\b/.test(text) || /USB_STORAGE\s*[:=,]\s*ALLOWED/i.test(text)) return 'ALLOWED';
    
    if (/GPO_STATUS\s*[:=,]\s*APPLIED/i.test(text)) return 'APPLIED';
    if (/GPO_STATUS\s*[:=,]\s*NOT_APPLIED/i.test(text)) return 'NOT_APPLIED';

    if (/\bTERMINATED\b/.test(text) || /\bRESIGNED\b/.test(text)) return 'TERMINATED';
    if (/\bACTIVE\b/.test(text)) return 'ACTIVE';
    if (/\bCANCELLED\b/.test(text) || /\bREVOKED\b/.test(text)) return 'CANCELLED';
    
    if (/\bEXPIRED\b/.test(text)) return 'EXPIRED';
    if (/\bVALID\b/.test(text)) return 'VALID';
    
    if (/\bENABLED\b/.test(text)) return 'ENABLED';
    if (/\bDISABLED\b/.test(text)) return 'DISABLED';

    return null;
  }

  public static areStatusesContradictory(statuses: string[]): boolean {
    const s = new Set(statuses);
    if (s.has('BLOCKED') && s.has('ALLOWED')) return true;
    if (s.has('APPLIED') && s.has('NOT_APPLIED')) return true;
    if (s.has('ACTIVE') && (s.has('TERMINATED') || s.has('CANCELLED'))) return true;
    if (s.has('VALID') && s.has('EXPIRED')) return true;
    if (s.has('ENABLED') && s.has('DISABLED')) return true;
    return false;
  }
}
