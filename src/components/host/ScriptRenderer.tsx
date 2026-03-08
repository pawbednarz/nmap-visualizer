import { AlertTriangle, CheckCircle2, XCircle, ExternalLink, Key, Globe, Shield } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Badge } from '@/components/ui/Badge';
import { cn } from '@/lib/cn';
import { parseScript, type ParsedScript } from '@/lib/script-parsers';

interface ScriptRendererProps {
  id: string;
  output: string;
}

export function ScriptRenderer({ id, output }: ScriptRendererProps) {
  const parsed = parseScript(id, output);
  return <DispatchedScript parsed={parsed} />;
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatcher
// ──────────────────────────────────────────────────────────────────────────────

function DispatchedScript({ parsed }: { parsed: ParsedScript }) {
  switch (parsed.type) {
    case 'http-title':    return <HttpTitle {...parsed} />;
    case 'ssl-cert':      return <SslCert {...parsed} />;
    case 'smb-security-mode': return <SmbSecurityMode {...parsed} />;
    case 'http-methods':  return <HttpMethods {...parsed} />;
    case 'ftp-anon':      return <FtpAnon {...parsed} />;
    case 'ssh-hostkey':   return <SshHostkey {...parsed} />;
    case 'dns-recursion': return <DnsRecursion {...parsed} />;
    case 'http-robots':   return <HttpRobots {...parsed} />;
    case 'vuln':          return <VulnScript {...parsed} />;
    case 'raw':           return <RawScript {...parsed} />;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Script-specific renderers
// ──────────────────────────────────────────────────────────────────────────────

function HttpTitle({ title, isRedirect }: Extract<ParsedScript, { type: 'http-title' }>) {
  return (
    <div className="flex items-center gap-2">
      <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
      <span className={cn('text-xs', isRedirect ? 'text-slate-400 italic' : 'text-slate-200')}>
        {title}
      </span>
    </div>
  );
}

function SslCert({ subject, issuer, notAfter, daysUntilExpiry, fingerprints }: Extract<ParsedScript, { type: 'ssl-cert' }>) {
  const expired = daysUntilExpiry !== null && daysUntilExpiry < 0;
  const expiringSoon = daysUntilExpiry !== null && daysUntilExpiry >= 0 && daysUntilExpiry < 30;

  return (
    <div className="space-y-2 text-xs">
      {subject && <KVRow label="Subject" value={subject} />}
      {issuer && <KVRow label="Issuer" value={issuer} />}
      {notAfter && (
        <div className="flex gap-2">
          <span className="text-slate-500 w-16 shrink-0">Expires</span>
          <span className={cn(
            expired ? 'text-red-400 font-semibold' : expiringSoon ? 'text-orange-400' : 'text-slate-300'
          )}>
            {notAfter.toLocaleDateString()}{' '}
            {expired ? '(EXPIRED)' : expiringSoon ? `(in ${daysUntilExpiry}d — expiring soon)` : `(${formatDistanceToNow(notAfter, { addSuffix: true })})`}
          </span>
        </div>
      )}
      {fingerprints.map((fp) => (
        <KVRow key={fp.algo} label={fp.algo} value={fp.value} mono />
      ))}
    </div>
  );
}

function SmbSecurityMode({ fields }: Extract<ParsedScript, { type: 'smb-security-mode' }>) {
  if (fields.length === 0) return <RawFallback text="(no structured output)" />;
  return (
    <div className="space-y-1 text-xs">
      {fields.map((f) => {
        const isDangerous = f.value.includes('dangerous') || f.value.includes('disabled');
        return (
          <div key={f.key} className="flex gap-2">
            <span className="text-slate-500 w-32 shrink-0 capitalize">{f.key}</span>
            <span className={cn('text-slate-300 flex-1', isDangerous && 'text-orange-400 font-medium')}>
              {f.value}
              {isDangerous && <AlertTriangle className="w-3 h-3 inline ml-1 text-orange-400" />}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function HttpMethods({ methods, risky }: Extract<ParsedScript, { type: 'http-methods' }>) {
  if (methods.length === 0) return <RawFallback text="(no methods listed)" />;
  return (
    <div className="flex flex-wrap gap-1">
      {methods.map((m) => (
        <Badge key={m} variant={risky.includes(m) ? 'orange' : 'muted'}>
          {m}
          {risky.includes(m) && <AlertTriangle className="w-2.5 h-2.5 inline ml-1" />}
        </Badge>
      ))}
    </div>
  );
}

function FtpAnon({ allowed, message }: Extract<ParsedScript, { type: 'ftp-anon' }>) {
  return (
    <div className="flex items-start gap-2 text-xs">
      {allowed
        ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" />
        : <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />}
      <span className={cn(allowed ? 'text-orange-300' : 'text-slate-400')}>{message}</span>
    </div>
  );
}

function SshHostkey({ keys }: Extract<ParsedScript, { type: 'ssh-hostkey' }>) {
  if (keys.length === 0) return <RawFallback text="(no keys parsed)" />;
  return (
    <div className="space-y-1.5 text-xs">
      {keys.map((k, i) => (
        <div key={i} className="flex items-center gap-2">
          <Key className="w-3 h-3 text-slate-500 shrink-0" />
          <Badge variant="muted">{k.algo}</Badge>
          <span className="text-slate-500">{k.bits}b</span>
          <span className="font-mono text-[10px] text-slate-400 truncate">{k.fingerprint}</span>
        </div>
      ))}
    </div>
  );
}

function DnsRecursion({ allowed }: Extract<ParsedScript, { type: 'dns-recursion' }>) {
  return (
    <div className="flex items-center gap-2 text-xs">
      {allowed
        ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />
        : <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />}
      <span className={allowed ? 'text-orange-300' : 'text-slate-400'}>
        Recursive queries {allowed ? 'ENABLED (open resolver)' : 'disabled'}
      </span>
    </div>
  );
}

function HttpRobots({ disallowed, allowed }: Extract<ParsedScript, { type: 'http-robots' }>) {
  return (
    <div className="space-y-2 text-xs">
      {disallowed.length > 0 && (
        <div>
          <p className="text-slate-500 mb-1">Disallowed paths ({disallowed.length})</p>
          <div className="flex flex-wrap gap-1">
            {disallowed.slice(0, 12).map((p) => (
              <span key={p} className="font-mono text-[10px] text-slate-400 bg-surface px-1.5 py-0.5 rounded border border-surface-border">
                {p}
              </span>
            ))}
            {disallowed.length > 12 && (
              <span className="text-slate-500 text-[10px]">+{disallowed.length - 12} more</span>
            )}
          </div>
        </div>
      )}
      {allowed.length > 0 && (
        <div>
          <p className="text-slate-500 mb-1">Allowed paths</p>
          <div className="flex flex-wrap gap-1">
            {allowed.map((p) => (
              <span key={p} className="font-mono text-[10px] text-green-400/70 bg-surface px-1.5 py-0.5 rounded border border-surface-border">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VulnScript({ state, title, description, references }: Extract<ParsedScript, { type: 'vuln' }>) {
  const isVuln = state.toUpperCase().includes('VULNERABLE');
  const isLikely = state.toUpperCase().includes('LIKELY');

  return (
    <div className="space-y-2 text-xs">
      <div className="flex items-center gap-2">
        {isVuln
          ? <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
          : <Shield className="w-3.5 h-3.5 text-green-400 shrink-0" />}
        <Badge variant={isVuln ? 'red' : isLikely ? 'orange' : 'green'}>{state}</Badge>
        {title && <span className="text-slate-300 truncate">{title}</span>}
      </div>
      {description && (
        <p className="text-slate-400 leading-relaxed">{description.slice(0, 300)}{description.length > 300 ? '…' : ''}</p>
      )}
      {references.length > 0 && (
        <div className="flex flex-col gap-1">
          {references.slice(0, 3).map((ref) => (
            <a
              key={ref}
              href={ref}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-accent-cyan hover:underline truncate"
            >
              <ExternalLink className="w-3 h-3 shrink-0" />
              <span className="truncate">{ref}</span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function RawScript({ scriptId: _scriptId, output }: Extract<ParsedScript, { type: 'raw' }>) {
  return <RawFallback text={output} />;
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared primitives
// ──────────────────────────────────────────────────────────────────────────────

function KVRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <span className="text-slate-500 w-16 shrink-0">{label}</span>
      <span className={cn('text-slate-300 break-all flex-1', mono && 'font-mono text-[10px]')}>{value}</span>
    </div>
  );
}

function RawFallback({ text }: { text: string }) {
  return (
    <pre className="text-[10px] text-slate-400 font-mono bg-surface p-2 rounded-lg overflow-x-auto whitespace-pre-wrap break-words">
      {text.trim()}
    </pre>
  );
}
