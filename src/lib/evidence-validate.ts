export const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024; // 2 MiB per file
export const MAX_EVIDENCE_PER_INCIDENT = 25;

export type EvidenceFormat = 'text' | 'json' | 'ndjson' | 'csv' | 'yaml';

const EXTENSIONS: Record<string, EvidenceFormat> = {
  log: 'text',
  txt: 'text',
  json: 'json',
  ndjson: 'ndjson',
  jsonl: 'ndjson',
  csv: 'csv',
  yaml: 'yaml',
  yml: 'yaml',
};

// Browsers send varied MIME types for these files; accept only plain text families.
const ALLOWED_MIME = new Set([
  '',
  'text/plain',
  'text/csv',
  'text/x-log',
  'application/json',
  'application/x-ndjson',
  'application/jsonl',
  'application/x-yaml',
  'application/yaml',
  'text/yaml',
  'text/x-yaml',
  'application/octet-stream', // some OSes send this for .log/.ndjson; content checks below still apply
]);

export interface ValidatedEvidence {
  format: EvidenceFormat;
  text: string;
  safeFilename: string;
  lineCount: number;
}

export class EvidenceError extends Error {}

export function sanitizeFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? 'evidence';
  const cleaned = base.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 100);
  return cleaned || 'evidence';
}

export function validateEvidence(filename: string, mime: string, bytes: Uint8Array): ValidatedEvidence {
  if (bytes.byteLength === 0) throw new EvidenceError('File is empty.');
  if (bytes.byteLength > MAX_EVIDENCE_BYTES) throw new EvidenceError('File is larger than 2 MiB.');

  const safeFilename = sanitizeFilename(filename);
  const ext = safeFilename.includes('.') ? safeFilename.split('.').pop()!.toLowerCase() : '';
  const format = EXTENSIONS[ext];
  if (!format) throw new EvidenceError('Unsupported file type. Allowed: .log .txt .json .ndjson .jsonl .csv .yaml .yml');

  const baseMime = (mime.split(';')[0] ?? '').trim().toLowerCase();
  if (!ALLOWED_MIME.has(baseMime)) throw new EvidenceError('Unsupported content type.');

  // Reject binaries: NUL bytes or invalid UTF-8.
  if (bytes.includes(0)) throw new EvidenceError('File looks binary. Upload text logs or JSON only.');
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new EvidenceError('File is not valid UTF-8 text.');
  }

  if (format === 'json') {
    try {
      JSON.parse(text);
    } catch {
      throw new EvidenceError('File has a .json extension but is not valid JSON.');
    }
  }
  if (format === 'ndjson') {
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    for (const [i, l] of lines.entries()) {
      try {
        JSON.parse(l);
      } catch {
        throw new EvidenceError(`Line ${i + 1} is not valid JSON.`);
      }
    }
  }

  const lineCount = text.split(/\r?\n/).length;
  if (lineCount > 50_000) throw new EvidenceError('File has more than 50,000 lines.');
  return { format, text, safeFilename, lineCount };
}
