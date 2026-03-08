import { cn } from '@/lib/cn';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  glow?: 'cyan' | 'green' | 'none';
  onClick?: () => void;
}

export function Card({ children, className, glow = 'none', onClick }: CardProps) {
  const glowClass =
    glow === 'cyan' ? 'glow-cyan' : glow === 'green' ? 'glow-green' : '';

  return (
    <div
      className={cn(
        'glass-card p-4',
        glowClass,
        onClick && 'cursor-pointer hover:border-slate-500 transition-colors duration-200',
        className
      )}
      onClick={onClick}
    >
      {children}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  color?: string;
  subtitle?: string;
}

export function StatCard({ label, value, icon, color = 'text-accent-cyan', subtitle }: StatCardProps) {
  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">{label}</span>
        {icon && <div className="text-slate-500">{icon}</div>}
      </div>
      <div className="flex items-end gap-2">
        <span className={cn('text-3xl font-bold font-mono', color)}>{value}</span>
        {subtitle && <span className="text-sm text-slate-500 mb-1">{subtitle}</span>}
      </div>
    </Card>
  );
}
