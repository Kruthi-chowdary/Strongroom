/**
 * tickets.ts – single-use, 60-second download tickets bound to user+document.
 * Only sha256(ticket) is kept in memory. Redemption RE-RUNS authorize().
 */
import crypto from 'crypto';

interface Ticket { userId: string; docId: string; expires: number }
const tickets = new Map<string, Ticket>();
const TTL_MS = 60_000;

const h = (t: string) => crypto.createHash('sha256').update(t).digest('hex');

export function issueTicket(userId: string, docId: string): string {
  const now = Date.now();
  for (const [k, v] of tickets) if (v.expires < now) tickets.delete(k);
  const raw = crypto.randomBytes(32).toString('hex');
  tickets.set(h(raw), { userId, docId, expires: now + TTL_MS });
  return raw;
}

/** Single use: deleted the moment it is looked up. */
export function redeemTicket(raw: string): Ticket | null {
  const key = h(raw);
  const t = tickets.get(key);
  if (!t) return null;
  tickets.delete(key);
  return t.expires < Date.now() ? null : t;
}