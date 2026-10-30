import type { EvidenceFormat } from './evidence-validate';

export interface ParsedEvent {
  occurredAt: string; // ISO 8601
  lineNo: number;
  kind: 'deploy' | 'error' | 'warning' | 'recovery' | 'info';
  summary: string;
}

const MAX_EVENTS_PER_FILE = 500;
const ISO_RE = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/;

export function classify(line: string): ParsedEvent['kind'] {
  const l = line.toLowerCase();
  if (/\b(deploy|rollout|release|helm upgrade|image updated|merged|version \S+ (live|deployed))\b/.test(l)) return 'deploy';
  if (/\b(error|fatal|panic|exception|oomkilled|crashloopbackoff|5\d\d\b|timed? ?out|refused|failed)\b/.test(l)) return 'error';
  if (/\b(warn|warning|degraded|retrying|throttl|429)\b/.test(l)) return 'warning';
  if (/\b(recovered|resolved|healthy|back to normal|rolled back|rollback complete)\b/.test(l)) return 'recovery';
  return 'info';
}

function normaliseTs(raw: string): string | null {
  let s = raw.replace(' ', 'T');
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(s)) s += 'Z'; // assume UTC when no offset; shown as such in the UI
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function pickJsonTs(obj: Record<string, unknown>): string | null {
  for (const k of ['timestamp', 'time', 'ts', '@timestamp', 'created_at', 'startedAt', 'started_at']) {
    const v = obj[k];
    if (typeof v === 'string') {
      const n = normaliseTs(v);
      if (n) return n;
    }
    if (typeof v === 'number') {
      const ms = v > 1e12 ? v : v * 1000;
      const d = new Date(ms);
      if (!Number.isNaN(d.getTime())) return d.toISOString();
    }
  }
  return null;
}

function jsonSummary(obj: Record<string, unknown>, fallback: string): string {
  const parts = ['level', 'severity', 'service', 'event', 'msg', 'message', 'status', 'conclusion', 'name']
    .map((k) => (typeof obj[k] === 'string' || typeof obj[k] === 'number' ? `${k}=${obj[k]}` : ''))
    .filter(Boolean);
  return (parts.join(' ') || fallback).slice(0, 300);
}

/** Extract timestamped events from (already redacted) evidence text. Lines without timestamps are skipped. */
export function parseTimeline(text: string, format: EvidenceFormat): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);

  if (format === 'json') {
    try {
      const data: unknown = JSON.parse(text);
      const arr = Array.isArray(data) ? data : [data];
      arr.slice(0, MAX_EVENTS_PER_FILE).forEach((item, i) => {
        if (item && typeof item === 'object') {
          const ts = pickJsonTs(item as Record<string, unknown>);
          if (ts) {
            const summary = jsonSummary(item as Record<string, unknown>, JSON.stringify(item).slice(0, 300));
            events.push({ occurredAt: ts, lineNo: i + 1, kind: classify(summary), summary });
          }
        }
      });
    } catch {
      /* validated earlier */
    }
    return events;
  }

  for (let i = 0; i < lines.length && events.length < MAX_EVENTS_PER_FILE; i++) {
    const line = lines[i]!;
    if (!line.trim()) continue;
    if (format === 'ndjson') {
      try {
        const obj = JSON.parse(line) as Record<string, unknown>;
        const ts = pickJsonTs(obj);
        if (ts) {
          const summary = jsonSummary(obj, line.slice(0, 300));
          events.push({ occurredAt: ts, lineNo: i + 1, kind: classify(summary), summary });
        }
      } catch {
        /* skip */
      }
      continue;
    }
    const m = ISO_RE.exec(line);
    if (!m) continue;
    const ts = normaliseTs(m[1]!);
    if (!ts) continue;
    const summary = line.replace(m[1]!, '').trim().slice(0, 300);
    events.push({ occurredAt: ts, lineNo: i + 1, kind: classify(line), summary });
  }
  return events;
}
