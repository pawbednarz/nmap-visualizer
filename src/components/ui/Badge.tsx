import { cn } from '@/lib/cn';
import type { PortState } from '@/types/nmap';
import { PORT_STATE_BG } from '@/lib/colors';

interface BadgeProps {
  children: React.ReactNode;
  className?: string;
  variant?: 'default' | 'cyan' | 'green' | 'red' | 'orange' | 'purple' | 'muted';
}

const VARIANT_CLASSES: Record<string, string> = {
  default: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
  cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  green: 'bg-green-500/10 text-green-400 border-green-500/20',
  red: 'bg-red-500/10 text-red-400 border-red-500/20',
  orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  muted: 'bg-surface-muted text-slate-400 border-surface-border',
};

export function Badge({ children, className, variant = 'default' }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-mono font-medium border',
        VARIANT_CLASSES[variant],
        className
      )}
    >
      {children}
    </span>
  );
}

interface PortStateBadgeProps {
  state: PortState;
}

export function PortStateBadge({ state }: PortStateBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-mono font-medium border',
        PORT_STATE_BG[state]
      )}
    >
      {state}
    </span>
  );
}
