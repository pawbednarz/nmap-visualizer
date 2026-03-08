// ──────────────────────────────────────────────────────────────────────────────
// NSE script output parsers
//
// Each parser takes the raw `output` string from an NmapScript and returns a
// typed, structured result. The `ScriptRenderer` component dispatches on `type`
// to render appropriate UI.
// ──────────────────────────────────────────────────────────────────────────────

export type ParsedScript =
  | { type: 'http-title'; title: string; isRedirect: boolean }
  | { type: 'ssl-cert'; subject: string; issuer: string; notBefore: Date | null; notAfter: Date | null; daysUntilExpiry: number | null; fingerprints: { algo: string; value: string }[] }
  | { type: 'smb-security-mode'; fields: { key: string; value: string }[] }
  | { type: 'http-methods'; methods: string[]; risky: string[] }
  | { type: 'ftp-anon'; allowed: boolean; message: string }
  | { type: 'ssh-hostkey'; keys: { bits: string; fingerprint: string; algo: string }[] }
  | { type: 'banner'; text: string }
  | { type: 'dns-recursion'; allowed: boolean }
  | { type: 'http-robots'; disallowed: string[]; allowed: string[] }
  | { type: 'vuln'; state: 'VULNERABLE' | 'NOT VULNERABLE' | 'LIKELY VULNERABLE' | string; title: string; description: string; references: string[] }
  | { type: 'raw'; scriptId: string; output: string };

// ──────────────────────────────────────────────────────────────────────────────
// Individual parsers
// ──────────────────────────────────────────────────────────────────────────────

function parseHttpTitle(output: string): ParsedScript {
  const isRedirect = output.includes('Did not follow redirect');
  const redirectMatch = output.match(/redirect to (.+)/i);
  const title = redirectMatch
    ? `Redirects to: ${redirectMatch[1].trim()}`
    : output.replace(/\(.*?\)/g, '').trim() || '(no title)';
  return { type: 'http-title', title, isRedirect };
}

function parseSslCert(output: string): ParsedScript {
  const extract = (label: string) => {
    const m = output.match(new RegExp(`${label}:\\s*(.+)`));
    return m ? m[1].trim() : '';
  };

  const notBeforeStr = extract('Not valid before');
  const notAfterStr = extract('Not valid after');

  const parseDate = (s: string): Date | null => {
    if (!s) return null;
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  };

  const notAfter = parseDate(notAfterStr);
  const daysUntilExpiry = notAfter
    ? Math.ceil((notAfter.getTime() - Date.now()) / 86_400_000)
    : null;

  // Extract fingerprints (lines like "MD5:  xx xx xx" or "SHA-1: xx xx xx")
  const fingerprints: { algo: string; value: string }[] = [];
  for (const line of output.split('\n')) {
    const fm = line.match(/^\s*(MD5|SHA-?1|SHA-?256)[:\s]+(.+)/i);
    if (fm) fingerprints.push({ algo: fm[1].toUpperCase(), value: fm[2].trim() });
  }

  return {
    type: 'ssl-cert',
    subject: extract('Subject'),
    issuer: extract('Issuer'),
    notBefore: parseDate(notBeforeStr),
    notAfter,
    daysUntilExpiry,
    fingerprints,
  };
}

function parseSmbSecurityMode(output: string): ParsedScript {
  const fields: { key: string; value: string }[] = [];
  for (const line of output.split('\n')) {
    const m = line.match(/^\s*([\w_]+):\s*(.+)/);
    if (m) fields.push({ key: m[1].replace(/_/g, ' '), value: m[2].trim() });
  }
  return { type: 'smb-security-mode', fields };
}

const RISKY_HTTP_METHODS = new Set(['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PROPFIND', 'MKCOL']);

function parseHttpMethods(output: string): ParsedScript {
  const m = output.match(/Supported Methods:\s*(.+)/i);
  const methods = m ? m[1].split(/\s+/).filter(Boolean) : [];
  const risky = methods.filter((method) => RISKY_HTTP_METHODS.has(method.toUpperCase()));
  return { type: 'http-methods', methods, risky };
}

function parseFtpAnon(output: string): ParsedScript {
  const allowed = /allowed|230/i.test(output) && !/false|not allowed|disallowed/i.test(output);
  return { type: 'ftp-anon', allowed, message: output.trim() };
}

function parseSshHostkey(output: string): ParsedScript {
  const keys: { bits: string; fingerprint: string; algo: string }[] = [];
  for (const line of output.split('\n')) {
    // Format: "  2048 SHA256:xxxx (RSA)" or "  256 ab:cd:ef:... (ECDSA)"
    const m = line.match(/^\s*(\d+)\s+([\w+/=:]+)\s+\((\w+)\)/);
    if (m) keys.push({ bits: m[1], fingerprint: m[2], algo: m[3] });
  }
  return { type: 'ssh-hostkey', keys };
}

function parseDnsRecursion(output: string): ParsedScript {
  const allowed = /enabled|allowed/i.test(output);
  return { type: 'dns-recursion', allowed };
}

function parseHttpRobots(output: string): ParsedScript {
  const disallowed: string[] = [];
  const allowed: string[] = [];
  for (const line of output.split('\n')) {
    const d = line.match(/Disallow:\s*(.+)/i);
    if (d) disallowed.push(d[1].trim());
    const a = line.match(/Allow:\s*(.+)/i);
    if (a) allowed.push(a[1].trim());
  }
  return { type: 'http-robots', disallowed, allowed };
}

function parseVuln(scriptId: string, output: string): ParsedScript {
  const stateMatch = output.match(/State:\s*(.+)/i);
  const state = stateMatch ? stateMatch[1].trim() : 'UNKNOWN';

  const titleMatch = output.match(/^\s+(.+?)\n/);
  const title = titleMatch ? titleMatch[1].trim() : scriptId;

  const descMatch = output.match(/Description:\s*([\s\S]+?)(?=References:|IDs:|$)/i);
  const description = descMatch ? descMatch[1].trim() : '';

  const references: string[] = [];
  const refSection = output.match(/References:\s*([\s\S]+?)(?=\n\n|$)/i);
  if (refSection) {
    for (const line of refSection[1].split('\n')) {
      const url = line.trim();
      if (url.startsWith('http')) references.push(url);
    }
  }

  return { type: 'vuln' as const, state, title, description, references };
}

// ──────────────────────────────────────────────────────────────────────────────
// Main dispatcher
// ──────────────────────────────────────────────────────────────────────────────

export function parseScript(id: string, output: string): ParsedScript {
  const normalId = id.toLowerCase();

  if (normalId === 'http-title') return parseHttpTitle(output);
  if (normalId === 'ssl-cert') return parseSslCert(output);
  if (normalId === 'smb-security-mode' || normalId === 'smb2-security-mode') return parseSmbSecurityMode(output);
  if (normalId === 'http-methods') return parseHttpMethods(output);
  if (normalId === 'ftp-anon') return parseFtpAnon(output);
  if (normalId === 'ssh-hostkey') return parseSshHostkey(output);
  if (normalId === 'dns-recursion' || normalId === 'dns-server-recursion') return parseDnsRecursion(output);
  if (normalId === 'http-robots.txt') return parseHttpRobots(output);
  if (normalId.startsWith('vuln') || normalId.includes('-vuln') || normalId.endsWith('-cve')) {
    return parseVuln(id, output);
  }

  return { type: 'raw', scriptId: id, output };
}
