import { GoogleGenAI, Type } from '@google/genai';
import { AIRecommendation, AuditParameter } from './models.js';

let quotaExhaustedUntil = 0;

export async function evaluateEvidenceWithGemini(
  filename: string,
  extractedText: string,
  parameter: AuditParameter
): Promise<AIRecommendation | null> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }

  // Circuit breaker: skip if recently rate limited / quota exhausted
  if (Date.now() < quotaExhaustedUntil) {
    return null;
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: { 'User-Agent': 'aistudio-build' }
      }
    });

    const prompt = `You are an expert compliance auditor reviewing document evidence for an audit parameter.

Audit Parameter ID: ${parameter.id}
Parameter Title: ${parameter.parameter}
Category: ${parameter.category_name}
Required Evidence Types: ${parameter.required_evidence.join(', ')}

Document Filename: ${filename}
Document Text Sample:
"""
${extractedText.substring(0, 3500)}
"""

Evaluate whether this document provides valid evidence for this audit parameter.
Analyze whether it is a policy document vs technical/operational implementation evidence, check dates/expiry if present, and recommend a compliance status.
Note: You are providing an AI recommendation only. The deterministic audit engine calculates the final score.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.7-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are FileSentinel Audit AI, an objective regulatory compliance analyst. Perform precise evidence classification according to strict compliance standards.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            evidence_type: { type: Type.STRING, description: 'Type of evidence identified' },
            relevance: { type: Type.NUMBER, description: 'Relevance score between 0.0 and 1.0' },
            extracted_fields: {
              type: Type.OBJECT,
              properties: {
                person_name: { type: Type.STRING },
                certificate_status: { type: Type.STRING },
                issue_date: { type: Type.STRING },
                expiry_date: { type: Type.STRING },
                is_policy_only: { type: Type.BOOLEAN },
                is_implementation: { type: Type.BOOLEAN }
              }
            },
            reason: { type: Type.STRING, description: 'Clear explanation of evidence evaluation' },
            recommended_status: {
              type: Type.STRING,
              description: 'PASS, FAIL, REVIEW, NOT_APPLICABLE, or EVIDENCE_NOT_FOUND'
            },
            confidence: { type: Type.NUMBER, description: 'Confidence score between 0.0 and 1.0' }
          },
          required: ['evidence_type', 'relevance', 'reason', 'recommended_status', 'confidence']
        }
      }
    });

    if (!response.text) return null;

    const parsed = JSON.parse(response.text.trim());
    return {
      evidence_type: parsed.evidence_type || parameter.required_evidence[0] || 'DOC_EVIDENCE',
      relevance: typeof parsed.relevance === 'number' ? parsed.relevance : 0.85,
      extracted_fields: parsed.extracted_fields || {},
      reason: parsed.reason || 'AI evidence evaluation complete.',
      recommended_status: (parsed.recommended_status || 'REVIEW') as any,
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.80
    };
  } catch (err: any) {
    const errMsg = err?.message || String(err);
    const isRateLimit = errMsg.includes('429') || errMsg.includes('RESOURCE_EXHAUSTED') || errMsg.includes('Quota exceeded') || err?.status === 429 || errMsg.includes('503') || errMsg.includes('UNAVAILABLE') || err?.status === 503;
    if (isRateLimit) {
      quotaExhaustedUntil = Date.now() + 60000; // Cooldown for 60 seconds
      console.warn('[Audit AI] Gemini rate limit/quota reached (429). Pausing AI evidence evaluations for 60s; relying on deterministic engine.');
    } else {
      console.warn('[Audit AI] Gemini evidence evaluation skipped:', errMsg);
    }
    return null;
  }
}
