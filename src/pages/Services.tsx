import { useState, useMemo } from 'react';
import { motion, type Variants } from 'framer-motion';
import { Search } from 'lucide-react';
import { useActiveScan, useHasScans, useScanStore } from '@/store/scanStore';
import { HostDetail } from '@/components/host/HostDetail';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { getServiceColor } from '@/lib/colors';
import { cn } from '@/lib/cn';
import type { NmapHost } from '@/types/nmap';

interface ServiceEntry {
  port: number;
  protocol: string;
  hosts: NmapHost[];
  versions: Set<string>;
}

const CONTAINER: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.04 } },
};

const ITEM: Variants = {
  hidden: { opacity: 0, y: 10 },
  show: { opacity: 1, y: 0 },
};

export function Services() {
  const hasScans = useHasScans();
  const scan = useActiveScan();
  const { selectedHostId, selectHost } = useScanStore();
  const [search, setSearch] = useState('');
  const [activeService, setActiveService] = useState<string | null>(null);

  const serviceMap = useMemo(() => {
    if (!scan) return new Map<string, ServiceEntry>();
    const map = new Map<string, ServiceEntry>();
    for (const host of scan.hosts) {
      for (const port of host.openPorts) {
        const name = port.service?.name ?? 'unknown';
        if (!map.has(name)) {
          map.set(name, { port: port.portid, protocol: port.protocol, hosts: [], versions: new Set() });
        }
        const entry = map.get(name)!;
        entry.hosts.push(host);
        if (port.service?.version) entry.versions.add(port.service.version);
      }
    }
    return map;
  }, [scan]);

  const filteredServices = useMemo(() => {
    const entries = Array.from(serviceMap.entries())
      .sort((a, b) => b[1].hosts.length - a[1].hosts.length);
    if (!search) return entries;
    return entries.filter(([name]) => name.toLowerCase().includes(search.toLowerCase()));
  }, [serviceMap, search]);

  const activeServiceData = activeService ? serviceMap.get(activeService) : null;

  if (!hasScans || !scan) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        No scan loaded.
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">
      <div className="flex-1 flex flex-col gap-4 min-w-0">
        {/* Search */}
        <div className="relative w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search services…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-surface-elevated border border-surface-border rounded-xl text-sm text-slate-200 placeholder-slate-500 pl-9 pr-4 py-2 focus:outline-none focus:border-slate-500"
          />
        </div>

        {/* Service cards grid */}
        <motion.div
          variants={CONTAINER}
          initial="hidden"
          animate="show"
          className="flex-1 overflow-y-auto"
        >
          {activeService && activeServiceData ? (
            /* Expanded service view */
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setActiveService(null)}
                  className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  ← All Services
                </button>
                <h2 className="text-base font-bold text-white font-mono">{activeService}</h2>
                <Badge variant="cyan">{activeServiceData.hosts.length} hosts</Badge>
              </div>

              <Card>
                <div className="divide-y divide-surface-border">
                  {activeServiceData.hosts.map((host) => {
                    const matchingPorts = host.openPorts.filter(
                      (p) => (p.service?.name ?? 'unknown') === activeService
                    );
                    return (
                      <div
                        key={host.id}
                        onClick={() => selectHost(host.id === selectedHostId ? null : host.id)}
                        className={cn(
                          'flex items-center justify-between py-3 px-4 cursor-pointer hover:bg-surface-muted/30 transition-colors',
                          host.id === selectedHostId && 'bg-accent-cyan/5'
                        )}
                      >
                        <div>
                          <p className="text-sm font-mono text-slate-200">{host.displayName}</p>
                          {host.ipv4 && host.displayName !== host.ipv4 && (
                            <p className="text-xs text-slate-500 font-mono">{host.ipv4}</p>
                          )}
                        </div>
                        <div className="flex gap-2 flex-wrap justify-end">
                          {matchingPorts.map((p) => (
                            <div key={`${p.portid}/${p.protocol}`} className="text-right">
                              <Badge variant="muted" className="font-mono">
                                {p.portid}/{p.protocol}
                              </Badge>
                              {p.service?.version && (
                                <p className="text-xs text-slate-500 mt-0.5">{p.service.version}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Card>
            </div>
          ) : (
            /* Service grid */
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-5 gap-3">
              {filteredServices.map(([name, data], i) => (
                <motion.div key={name} variants={ITEM}>
                  <Card
                    className="cursor-pointer hover:border-slate-500 group"
                    onClick={() => setActiveService(name)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold font-mono"
                        style={{
                          background: `${getServiceColor(i)}15`,
                          color: getServiceColor(i),
                          border: `1px solid ${getServiceColor(i)}30`,
                        }}
                      >
                        {name.slice(0, 2).toUpperCase()}
                      </div>
                      <Badge variant="muted">{data.port}</Badge>
                    </div>
                    <p
                      className="text-sm font-medium font-mono group-hover:text-white transition-colors"
                      style={{ color: getServiceColor(i) }}
                    >
                      {name}
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      {data.hosts.length} {data.hosts.length === 1 ? 'host' : 'hosts'}
                    </p>
                    {data.versions && data.versions.size > 0 && (
                      <p className="text-[10px] text-slate-600 mt-1 font-mono truncate">
                        {Array.from(data.versions).slice(0, 1).join(', ')}
                      </p>
                    )}
                  </Card>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Host detail panel */}
      <HostDetail />
    </div>
  );
}
