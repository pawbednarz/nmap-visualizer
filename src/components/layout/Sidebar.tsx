import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  List,
  BarChart2,
  Globe,
  UploadCloud,
  Scan,
} from 'lucide-react';
import { cn } from '@/lib/cn';
import { useHasScans } from '@/store/scanStore';

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', requiresScan: false },
  { to: '/graph', icon: Network, label: 'Network Map', requiresScan: true },
  { to: '/hosts', icon: List, label: 'Host List', requiresScan: true },
  { to: '/ports', icon: BarChart2, label: 'Port Analysis', requiresScan: true },
  { to: '/services', icon: Globe, label: 'Services', requiresScan: true },
];

export function Sidebar() {
  const hasScans = useHasScans();

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
      <nav className="flex-1 px-3 py-4 space-y-1">
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
      </nav>

      {/* Upload shortcut */}
      <div className="px-3 pb-4">
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
