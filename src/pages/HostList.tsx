import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, SlidersHorizontal, X } from 'lucide-react';
import { useScanStore, useActiveScan, useHasScans } from '@/store/scanStore';
import { HostDetail } from '@/components/host/HostDetail';
import { Badge, PortStateBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/cn';
import type { HostState } from '@/types/nmap';

const STATE_OPTIONS: { label: string; value: HostState | 'all' }[] = [
  { label: 'All', value: 'all' },
  { label: 'Up', value: 'up' },
  { label: 'Down', value: 'down' },
];

export function HostList() {
  const hasScans = useHasScans();
  const scan = useActiveScan();
  const { filteredHosts, selectedHostId, selectHost, filter, setFilter, clearFilter } =
    useScanStore();
  const [showFilters, setShowFilters] = useState(false);

  if (!hasScans || !scan) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        No scan loaded.
      </div>
    );
  }

  const uniqueServices = scan.uniqueServices.sort();

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">
      {/* Main panel */}
      <div className="flex-1 flex flex-col gap-4 min-w-0">
        {/* Toolbar */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative flex-1 min-w-48">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search hosts, IPs, MACs…"
              value={filter.search}
              onChange={(e) => setFilter({ search: e.target.value })}
              className="w-full bg-surface-elevated border border-surface-border rounded-xl text-sm text-slate-200 placeholder-slate-500 pl-9 pr-4 py-2 focus:outline-none focus:border-slate-500 transition-colors"
            />
          </div>

          {/* State filter pills */}
          <div className="flex items-center gap-1 bg-surface-elevated border border-surface-border rounded-xl p-1">
            {STATE_OPTIONS.map(({ label, value }) => (
              <button
                key={value}
                onClick={() => setFilter({ state: value })}
                className={cn(
                  'px-3 py-1 rounded-lg text-xs font-medium transition-all duration-150',
                  filter.state === value
                    ? 'bg-accent-cyan text-surface'
                    : 'text-slate-400 hover:text-slate-200'
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Filters toggle */}
          <Button
            variant={showFilters ? 'primary' : 'secondary'}
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Filters
          </Button>

          {/* Clear filters */}
          {(filter.search || filter.state !== 'all' || filter.service || filter.os) && (
            <Button variant="ghost" size="sm" onClick={clearFilter}>
              <X className="w-3.5 h-3.5" />
              Clear
            </Button>
          )}

          <span className="text-xs text-slate-500 ml-auto font-mono">
            {filteredHosts.length} / {scan.hosts.length} hosts
          </span>
        </div>

        {/* Extra filters */}
        {showFilters && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="flex items-center gap-3 flex-wrap p-4 bg-surface-elevated border border-surface-border rounded-xl"
          >
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Min open ports</label>
              <input
                type="number"
                min={0}
                value={filter.minOpenPorts}
                onChange={(e) => setFilter({ minOpenPorts: Number(e.target.value) })}
                className="w-16 bg-surface border border-surface-border rounded-lg text-sm text-slate-200 px-2 py-1 focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Service</label>
              <select
                value={filter.service}
                onChange={(e) => setFilter({ service: e.target.value })}
                className="bg-surface border border-surface-border rounded-lg text-sm text-slate-200 px-2 py-1 focus:outline-none"
              >
                <option value="">Any</option>
                {uniqueServices.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">OS</label>
              <input
                type="text"
                placeholder="e.g. Windows"
                value={filter.os}
                onChange={(e) => setFilter({ os: e.target.value })}
                className="bg-surface border border-surface-border rounded-lg text-sm text-slate-200 px-2 py-1 focus:outline-none w-32"
              />
            </div>
          </motion.div>
        )}

        {/* Host table */}
        <div className="flex-1 overflow-y-auto glass-card">
          {filteredHosts.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-slate-500 text-sm">
              No hosts match the current filters.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border">
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">
                    Host
                  </th>
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider hidden md:table-cell">
                    IP
                  </th>
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider hidden lg:table-cell">
                    OS
                  </th>
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">
                    Status
                  </th>
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">
                    Open Ports
                  </th>
                  <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider hidden xl:table-cell">
                    Top Services
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredHosts.map((host) => (
                  <tr
                    key={host.id}
                    onClick={() => selectHost(host.id === selectedHostId ? null : host.id)}
                    className={cn(
                      'border-b border-surface-border/50 cursor-pointer transition-colors duration-100',
                      host.id === selectedHostId
                        ? 'bg-accent-cyan/5 border-l-2 border-l-accent-cyan'
                        : 'hover:bg-surface-muted/40'
                    )}
                  >
                    <td className="px-4 py-3 font-mono text-slate-200">
                      {host.displayName}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 text-xs hidden md:table-cell">
                      {host.ipv4 ?? host.ipv6 ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs truncate max-w-32 hidden lg:table-cell">
                      {host.topOs ?? '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1.5 text-xs font-medium',
                          host.state === 'up' ? 'text-accent-green' : 'text-accent-red'
                        )}
                      >
                        <span
                          className={cn(
                            'w-1.5 h-1.5 rounded-full',
                            host.state === 'up' ? 'bg-accent-green' : 'bg-accent-red'
                          )}
                        />
                        {host.state}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="cyan">{host.openPortCount}</Badge>
                    </td>
                    <td className="px-4 py-3 hidden xl:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {host.openPorts.slice(0, 4).map((p) => (
                          <PortStateBadge key={`${p.portid}/${p.protocol}`} state={p.state} />
                        ))}
                        {host.openPorts.length > 4 && (
                          <Badge variant="muted">+{host.openPorts.length - 4}</Badge>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Host detail side panel */}
      <HostDetail />
    </div>
  );
}
