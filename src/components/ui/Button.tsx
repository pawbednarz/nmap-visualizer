import { cn } from '@/lib/cn';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

const VARIANT: Record<string, string> = {
  primary:
    'bg-accent-cyan text-surface font-semibold hover:bg-cyan-300 active:bg-cyan-500',
  secondary:
    'bg-surface-muted text-slate-200 border border-surface-border hover:bg-slate-700 hover:border-slate-500',
  ghost: 'text-slate-400 hover:text-slate-200 hover:bg-surface-muted',
  danger: 'bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20',
};

const SIZE: Record<string, string> = {
  sm: 'px-3 py-1.5 text-xs rounded-lg',
  md: 'px-4 py-2 text-sm rounded-xl',
  lg: 'px-6 py-3 text-base rounded-xl',
};

export function Button({
  variant = 'secondary',
  size = 'md',
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex items-center gap-2 font-medium transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed',
        VARIANT[variant],
        SIZE[size],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
