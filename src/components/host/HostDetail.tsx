import { motion, AnimatePresence } from 'framer-motion';
import { X, Monitor, Globe, Cpu, Wifi, Shield, Terminal, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { useState } from 'react';
import { useSelectedHost, useScanStore } from '@/store/scanStore';
import { Badge, PortStateBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ScriptRenderer } from '@/components/host/ScriptRenderer';
import { lookupPortCves, lookupHostCves } from '@/lib/cve-lookup';
import type { NmapPort, NmapScript } from '@/types/nmap';
import type { CveEntry } from '@/lib/cve-data';
import { cn } from '@/lib/cn';

const SEVERITY_BADGE: Record<string, 'red' | 'orange' | 'cyan' | 'muted'> = {
  critical: 'red',
  high: 'orange',
  medium: 'cyan',
  low: 'muted',
};

export function HostDetail() {
  const host = useSelectedHost();
  const { selectHost } = useScanStore();

  return (
    <AnimatePresence>
      {host && (
        <motion.aside
          key={host.id}
          initial={{ x: '100%', opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: '100%', opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="w-96 shrink-0 h-full overflow-y-auto border-l border-surface-border bg-surface-elevated flex flex-col"
        >
          {/* Header */}
          <div className="flex items-start justify-between p-5 border-b border-surface-border">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div
                  className={cn(
                    'w-2 h-2 rounded-full',
                    host.state === 'up' ? 'bg-accent-green animate-pulse-slow' : 'bg-accent-red'
                  )}
                />
                <Badge variant={host.state === 'up' ? 'green' : 'red'}>{host.state}</Badge>
              </div>
              <h2 className="text-base font-bold text-white font-mono">{host.displayName}</h2>
              {host.ipv4 && host.displayName !== host.ipv4 && (
                <p className="text-xs text-slate-400 font-mono mt-0.5">{host.ipv4}</p>
              )}
            </div>
            <Button variant="ghost" size="sm" onClick={() => selectHost(null)}>
              <X className="w-4 h-4" />
            </Button>
          </div>

          {/* Sections */}
          <div className="flex-1 divide-y divide-surface-border">
            {/* Identity */}
            <Section icon={<Monitor className="w-4 h-4" />} title="Identity">
              <InfoRow label="IPv4" value={host.ipv4} mono />
              <InfoRow label="IPv6" value={host.ipv6} mono />
              <InfoRow label="MAC" value={host.mac} mono />
              <InfoRow label="Vendor" value={host.macVendor} />
              {host.hostnames.map((h) => (
                <InfoRow key={h.name} label={`Hostname (${h.type})`} value={h.name} mono />
              ))}
            </Section>

            {/* OS */}
            {host.os && host.os.matches.length > 0 && (
              <Section icon={<Cpu className="w-4 h-4" />} title="OS Detection">
                {host.os.matches.slice(0, 3).map((m) => (
                  <div key={m.name} className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-xs text-slate-300 truncate flex-1">{m.name}</span>
                    <Badge variant="muted">{m.accuracy}%</Badge>
                  </div>
                ))}
              </Section>
            )}

            {/* Ports */}
            <Section icon={<Globe className="w-4 h-4" />} title={`Ports (${host.ports.length})`}>
              <div className="space-y-1.5 max-h-80 overflow-y-auto">
                {host.ports.map((port) => (
                  <PortRow key={`${port.portid}/${port.protocol}`} port={port} />
                ))}
              </div>
            </Section>

            {/* CVE Findings */}
            <CveFindingsSection host={host} />

            {/* Host Scripts */}
            {host.scripts && host.scripts.length > 0 && (
              <Section icon={<Terminal className="w-4 h-4" />} title="Host Scripts">
                {host.scripts.map((script) => (
                  <ScriptBlock key={script.id} script={script} />
                ))}
              </Section>
            )}

            {/* Port Scripts */}
            {host.ports.some((p) => p.scripts && p.scripts.length > 0) && (
              <Section icon={<Shield className="w-4 h-4" />} title="Port Scripts">
                {host.ports
                  .filter((p) => p.scripts && p.scripts.length > 0)
                  .map((port) =>
                    (port.scripts ?? []).map((script) => (
                      <div key={`${port.portid}-${script.id}`} className="mb-3">
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="text-xs text-slate-500 font-mono">
                            {port.portid}/{port.protocol}
                          </span>
                          <Badge variant="cyan">{script.id}</Badge>
                        </div>
                        <ScriptRenderer id={script.id} output={script.output} />
                      </div>
                    ))
                  )}
              </Section>
            )}

            {/* Network info */}
            {host.reason && (
              <Section icon={<Wifi className="w-4 h-4" />} title="Network">
                <InfoRow label="Up reason" value={host.reason} />
              </Section>
            )}
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Port row with inline CVE badges
// ──────────────────────────────────────────────────────────────────────────────

function PortRow({ port }: { port: NmapPort }) {
  const cves = lookupPortCves(port);
  const hasCves = cves.length > 0;
  const topSeverity = hasCves ? cves[0].severity : null;

  return (
    <div className={cn(
      'flex items-center gap-2 text-xs group rounded px-1 -mx-1',
      hasCves && 'bg-red-500/5'
    )}>
      <span className="font-mono text-slate-400 w-14 shrink-0">
        {port.portid}/{port.protocol}
      </span>
      <PortStateBadge state={port.state} />
      {port.service && (
        <span className="text-slate-300 truncate flex-1">
          {port.service.name}
          {port.service.version && (
            <span className="text-slate-500 ml-1">{port.service.version}</span>
          )}
        </span>
      )}
      {hasCves && topSeverity && (
        <Badge variant={SEVERITY_BADGE[topSeverity] ?? 'red'} className="shrink-0">
          <AlertTriangle className="w-2.5 h-2.5 mr-1" />
          {cves.length}
        </Badge>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// CVE findings section
// ──────────────────────────────────────────────────────────────────────────────

function CveFindingsSection({ host }: { host: ReturnType<typeof useSelectedHost> }) {
  const [expanded, setExpanded] = useState(false);
  if (!host) return null;

  const findings = lookupHostCves(host);
  if (findings.length === 0) return null;

  const allCves = findings.flatMap((f) => f.cves.map((cve) => ({ port: f.port, cve })));
  const criticalCount = allCves.filter((x) => x.cve.severity === 'critical').length;

  return (
    <Section
      icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
      title={`Vulnerability Findings (${allCves.length})`}
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200 mb-2 w-full text-left"
      >
        {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        <span>
          {criticalCount > 0 && <span className="text-red-400 font-semibold">{criticalCount} critical · </span>}
          {allCves.length} total findings
        </span>
      </button>

      {expanded && (
        <div className="space-y-2.5">
          {allCves.map(({ port, cve }, i) => (
            <CveCard key={`${cve.id}-${i}`} port={port} cve={cve} />
          ))}
        </div>
      )}
    </Section>
  );
}

function CveCard({ port, cve }: { port: NmapPort; cve: CveEntry }) {
  return (
    <div className="bg-surface rounded-lg p-2.5 border border-surface-border space-y-1.5">
      <div className="flex items-center gap-2 flex-wrap">
        <Badge variant={SEVERITY_BADGE[cve.severity] ?? 'red'}>{cve.severity.toUpperCase()}</Badge>
        <span className="font-mono text-xs text-slate-300">{cve.id}</span>
        <span className="text-[10px] text-slate-500 font-mono ml-auto">
          port {port.portid}/{port.protocol}
        </span>
      </div>
      <p className="text-[11px] text-slate-400 leading-relaxed">{cve.description}</p>
      {cve.portHintNote && (
        <p className="text-[10px] text-orange-400/80 italic">{cve.portHintNote}</p>
      )}
      {cve.cvssScore >= 7 && (
        <div className="text-[10px] font-mono text-slate-500">
          CVSS: <span className={cve.cvssScore >= 9 ? 'text-red-400' : 'text-orange-400'}>{cve.cvssScore}</span>
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Script block with structured rendering
// ──────────────────────────────────────────────────────────────────────────────

function ScriptBlock({ script }: { script: NmapScript }) {
  return (
    <div className="mb-3">
      <Badge variant="purple" className="mb-1.5">
        {script.id}
      </Badge>
      <ScriptRenderer id={script.id} output={script.output} />
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub-components
// ──────────────────────────────────────────────────────────────────────────────

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-slate-500">{icon}</span>
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value?: string;
  mono?: boolean;
}) {
  if (!value) return null;
  return (
    <div className="flex gap-2 text-xs mb-1.5">
      <span className="text-slate-500 shrink-0 w-28">{label}</span>
      <span className={cn('text-slate-300 break-all', mono && 'font-mono')}>{value}</span>
    </div>
  );
}
