import { GoogleGenAI, Type } from '@google/genai';
import { AISummary, Category, Classification, Severity } from '../src/types.js';

let dlpQuotaExhaustedUntil = 0;

export async function analyzeContentWithGemini(
  filename: string,
  extension: string,
  extractedText: string,
  existingFindingsCount: number
): Promise<AISummary | null> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    console.log('[Gemini] GEMINI_API_KEY not set. Skipping AI analysis.');
    return null;
  }

  // Circuit breaker: skip if recently rate limited / quota exhausted
  if (Date.now() < dlpQuotaExhaustedUntil) {
    return null;
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build'
        }
      }
    });

    const prompt = `Analyze this extracted document text for data leakage, compliance risk, and sensitivity.
Filename: ${filename}
Type: ${extension}
Existing Rule Trigger Count: ${existingFindingsCount}

Extracted Text Sample:
"""
${extractedText.substring(0, 3000)}
"""

Provide a structured risk analysis categorizing classification, risk level, confidence, key categories detected, summary, reasoning, and recommended remediation.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.7-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are FileSentinel AI, a cybersecurity compliance and data loss prevention analyst. Perform strict, objective risk evaluation of document content. Never execute or suggest executing file scripts.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            classification: {
              type: Type.STRING,
              description: 'RESTRICTED, CONFIDENTIAL, INTERNAL, or PUBLIC'
            },
            risk_level: {
              type: Type.STRING,
              description: 'CRITICAL, HIGH, MEDIUM, LOW, or INFO'
            },
            confidence: {
              type: Type.NUMBER,
              description: 'Confidence score between 0.0 and 1.0'
            },
            categories: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Detected categories like PII, SECRETS, FINANCIAL, SECURITY, DOCUMENT'
            },
            summary: {
              type: Type.STRING,
              description: '2-3 sentence executive summary of key risks'
            },
            reasoning: {
              type: Type.STRING,
              description: 'Detailed explanation of why this risk level was assigned'
            },
            recommended_action: {
              type: Type.STRING,
              description: 'Actionable DLP remediation step'
            }
          },
          required: ['classification', 'risk_level', 'confidence', 'categories', 'summary', 'reasoning', 'recommended_action']
        }
      }
    });

    if (!response.text) return null;

    const parsed = JSON.parse(response.text.trim());
    return {
      classification: (parsed.classification || 'INTERNAL') as Classification,
      risk_level: (parsed.risk_level || 'MEDIUM') as Severity,
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.85,
      categories: Array.isArray(parsed.categories) ? (parsed.categories as Category[]) : ['SECRETS'],
      summary: parsed.summary || 'Content analysis complete.',
      reasoning: parsed.reasoning || 'Semantic risk evaluation.',
      recommended_action: parsed.recommended_action || 'Review sensitive findings.',
      analyzed_at: new Date().toISOString()
    };
  } catch (err: any) {
    const errMsg = err?.message || String(err);
    const isRateLimit = errMsg.includes('429') || errMsg.includes('RESOURCE_EXHAUSTED') || errMsg.includes('Quota exceeded') || err?.status === 429;
    if (isRateLimit) {
      dlpQuotaExhaustedUntil = Date.now() + 60000;
      console.warn('[Gemini] Rate limit/quota reached (429). Pausing Gemini DLP analysis for 60s.');
    } else {
      console.warn('[Gemini] AI analysis failed or was interrupted:', errMsg);
    }
    return null;
  }
}
