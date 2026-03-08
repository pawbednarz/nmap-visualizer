import { motion, AnimatePresence } from 'framer-motion';
import { X, Monitor, Globe, Cpu, Wifi, Shield, Terminal } from 'lucide-react';
import { useSelectedHost, useScanStore } from '@/store/scanStore';
import { Badge, PortStateBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/cn';

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
                  <div
                    key={`${port.portid}/${port.protocol}`}
                    className="flex items-center gap-2 text-xs group"
                  >
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
                  </div>
                ))}
              </div>
            </Section>

            {/* Scripts */}
            {host.scripts && host.scripts.length > 0 && (
              <Section icon={<Terminal className="w-4 h-4" />} title="Host Scripts">
                {host.scripts.map((script) => (
                  <div key={script.id} className="mb-3">
                    <Badge variant="purple" className="mb-1">
                      {script.id}
                    </Badge>
                    <pre className="text-[10px] text-slate-400 font-mono bg-surface p-2 rounded-lg overflow-x-auto whitespace-pre-wrap break-words">
                      {script.output.trim()}
                    </pre>
                  </div>
                ))}
              </Section>
            )}

            {/* Port scripts */}
            {host.ports.some((p) => p.scripts && p.scripts.length > 0) && (
              <Section icon={<Shield className="w-4 h-4" />} title="Port Scripts">
                {host.ports
                  .filter((p) => p.scripts && p.scripts.length > 0)
                  .map((port) =>
                    (port.scripts ?? []).map((script) => (
                      <div key={`${port.portid}-${script.id}`} className="mb-3">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs text-slate-500 font-mono">
                            {port.portid}/{port.protocol}
                          </span>
                          <Badge variant="cyan">{script.id}</Badge>
                        </div>
                        <pre className="text-[10px] text-slate-400 font-mono bg-surface p-2 rounded-lg overflow-x-auto whitespace-pre-wrap break-words">
                          {script.output.trim()}
                        </pre>
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
