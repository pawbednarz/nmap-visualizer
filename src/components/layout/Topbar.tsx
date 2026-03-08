import { useLocation } from 'react-router-dom';
import { useScanStore, useActiveScan } from '@/store/scanStore';
import { Button } from '@/components/ui/Button';
import { Trash2, ChevronDown } from 'lucide-react';
import { format } from 'date-fns';

const PAGE_TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/graph': 'Network Map',
  '/hosts': 'Host List',
  '/ports': 'Port Analysis',
  '/services': 'Services',
  '/upload': 'Load Scan',
};

export function Topbar() {
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] ?? 'nmap Visualizer';
  const activeScan = useActiveScan();
  const { scans, activeScanIndex, setActiveScan, clearAll } = useScanStore();

  return (
    <header className="h-14 shrink-0 flex items-center justify-between px-6 border-b border-surface-border bg-surface-elevated">
      <h1 className="text-base font-semibold text-white">{title}</h1>

      <div className="flex items-center gap-3">
        {scans.length > 0 && (
          <>
            {/* Scan selector */}
            {scans.length > 1 && (
              <div className="relative">
                <select
                  value={activeScanIndex}
                  onChange={(e) => setActiveScan(Number(e.target.value))}
                  className="appearance-none bg-surface-muted border border-surface-border text-slate-300 text-sm rounded-lg px-3 py-1.5 pr-8 focus:outline-none focus:border-slate-500"
                >
                  {scans.map((scan, i) => (
                    <option key={i} value={i}>
                      {scan.args.split(' ')[0] ?? `Scan ${i + 1}`}
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-3 h-3 text-slate-400 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
              </div>
            )}

            {/* Scan info */}
            {activeScan && (
              <div className="text-xs text-slate-500 font-mono">
                {format(new Date(activeScan.startTime * 1000), 'dd MMM yyyy HH:mm')}
                {' · '}
                {activeScan.upHosts} hosts up
              </div>
            )}

            <Button variant="danger" size="sm" onClick={clearAll}>
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </Button>
          </>
        )}
      </div>
    </header>
  );
}
