/**
 * Best-effort redaction of secrets and common sensitive values. Applied to evidence before
 * it is stored, so neither the UI, the report, nor any model provider sees the raw values.
 * Pattern-based redaction cannot catch everything; this limit is documented in docs/THREAT_MODEL.md.
 */
const RULES: Array<{ name: string; re: RegExp }> = [
  // All quantifiers are bounded so crafted input cannot cause catastrophic backtracking.
  { name: 'private_key', re: /-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----[\s\S]{0,16000}?-----END [A-Z ]{0,20}PRIVATE KEY-----/g },
  { name: 'aws_access_key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'github_token', re: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g },
  { name: 'slack_token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'openai_style_key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'bearer', re: /\b(Bearer|Basic)[ \t]{1,5}[A-Za-z0-9._~+/=-]{12,}/g },
  {
    name: 'secret_assignment',
    re: /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(["']?[ \t]{0,5}[:=][ \t]{0,5}["']?)([^\s"',;}{]{4,})/gi,
  },
  { name: 'url_credentials', re: /\b([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s:@/]{1,256}:[^\s@/]{1,256}@/gi },
  { name: 'email', re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b/g },
  { name: 'card_number', re: /\b(?:\d[ -]?){13,16}\b/g },
];

export interface RedactionResult {
  text: string;
  count: number;
  byRule: Record<string, number>;
}

function luhn(raw: string): boolean {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 16) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

export function redact(input: string): RedactionResult {
  let text = input;
  let count = 0;
  const byRule: Record<string, number> = {};
  for (const { name, re } of RULES) {
    text = text.replace(re, (...m: string[]) => {
      if (name === 'card_number' && !luhn(m[0]!)) return m[0]!; // avoid redacting epoch ms, ids
      count++;
      byRule[name] = (byRule[name] ?? 0) + 1;
      if (name === 'secret_assignment') return `${m[1]}${m[2]}[REDACTED:${name}]`;
      if (name === 'url_credentials') return `${m[1]}[REDACTED:credentials]@`;
      return `[REDACTED:${name}]`;
    });
  }
  return { text, count, byRule };
}

/**
 * Flags text that looks like instructions aimed at an AI system. Flagged evidence is still
 * stored and analysed as data; the flag is shown to users and recorded as a risk. Nothing in
 * evidence is ever executed or followed.
 */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore (all |any )?(previous|prior|above) (instructions|prompts?)/i,
  /disregard (the )?(system|previous) (prompt|instructions)/i,
  /you are now (a|an|in) /i,
  /\b(system prompt|developer message)\b/i,
  /<[ \t]{0,5}\/?[ \t]{0,5}(system|assistant|instructions?)[ \t]{0,5}>/i,
  /\bexecute (the following|this) (command|shell)/i,
  /\b(curl|wget)[ \t]{1,5}[^\s|]{1,500}[ \t]{0,5}\|[ \t]{0,5}(sh|bash)\b/i,
];

export function detectInjection(text: string): { count: number; lines: number[] } {
  const lines: number[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const l = line.slice(0, 4000);
    if (INJECTION_PATTERNS.some((re) => re.test(l))) lines.push(i + 1);
  });
  return { count: lines.length, lines };
}
