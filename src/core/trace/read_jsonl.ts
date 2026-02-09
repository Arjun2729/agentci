import fs from 'fs';
import { TraceEvent } from '../types';

export function readJsonl(path: string): TraceEvent[] {
  const content = fs.readFileSync(path, 'utf8');
  const lines = content.split(/\r?\n/);
  const events: TraceEvent[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const parsed = JSON.parse(line) as TraceEvent;
      if (parsed && typeof parsed === 'object' && parsed.type) {
        events.push(parsed);
      }
    } catch {
      if (i === lines.length - 1) {
        // tolerate partial last line on crash
        break;
      }
    }
  }

  return events;
}
