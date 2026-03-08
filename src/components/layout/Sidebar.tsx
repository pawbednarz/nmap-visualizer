import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  List,
  BarChart2,
  Globe,
  UploadCloud,
  Scan,
  X,
  FileText,
} from 'lucide-react';
import { cn } from '@/lib/cn';
import { useHasScans, useScanStore } from '@/store/scanStore';

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', requiresScan: false },
  { to: '/graph', icon: Network, label: 'Network Map', requiresScan: true },
  { to: '/hosts', icon: List, label: 'Host List', requiresScan: true },
  { to: '/ports', icon: BarChart2, label: 'Port Analysis', requiresScan: true },
  { to: '/services', icon: Globe, label: 'Services', requiresScan: true },
];

export function Sidebar() {
  const hasScans = useHasScans();
  const { scans, activeScanIndex, setActiveScan, removeScan } = useScanStore();

  return (
    <aside className="w-60 shrink-0 flex flex-col bg-surface-elevated border-r border-surface-border">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-surface-border">
        <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
          <Scan className="w-4 h-4 text-accent-cyan" />
        </div>
        <div>
          <p className="text-sm font-bold text-white leading-none">nmap</p>
          <p className="text-xs text-accent-cyan font-mono leading-none mt-0.5">visualizer</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(({ to, icon: Icon, label, requiresScan }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150',
                isActive
                  ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-muted',
                requiresScan && !hasScans && 'opacity-40 pointer-events-none'
              )
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}

        {/* Saved scans */}
        {scans.length > 0 && (
          <div className="pt-4">
            <p className="px-3 mb-2 text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
              Loaded Scans
            </p>
            <div className="space-y-1">
              {scans.map((scan, i) => {
                const isActive = i === activeScanIndex;
                const label = scan.filename
                  ? scan.filename.replace(/\.xml$/i, '')
                  : scan.startStr || `Scan ${i + 1}`;
                return (
                  <div
                    key={i}
                    className={cn(
                      'flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all duration-150 group cursor-pointer',
                      isActive
                        ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-surface-muted border border-transparent'
                    )}
                    onClick={() => setActiveScan(i)}
                  >
                    <FileText className="w-3.5 h-3.5 shrink-0" />
                    <span className="flex-1 truncate font-mono">{label}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        removeScan(i);
                      }}
                      className={cn(
                        'opacity-0 group-hover:opacity-100 transition-opacity rounded p-0.5',
                        isActive ? 'hover:bg-accent-cyan/20 text-accent-cyan' : 'hover:bg-surface-muted text-slate-500'
                      )}
                      title="Remove scan"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </nav>

      {/* Upload shortcut */}
      <div className="px-3 pb-4 border-t border-surface-border pt-3">
        <NavLink
          to="/upload"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150 w-full',
              isActive
                ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-surface-muted'
            )
          }
        >
          <UploadCloud className="w-4 h-4 shrink-0" />
          <span>Load Scan</span>
        </NavLink>
      </div>
    </aside>
  );
}
