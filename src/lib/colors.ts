import type { PortState, HostState } from '@/types/nmap';

export const PORT_STATE_COLORS: Record<PortState, string> = {
  'open': '#00ff88',
  'closed': '#ff4444',
  'filtered': '#ff6b35',
  'open|filtered': '#ffd700',
  'closed|filtered': '#ff6b35',
};

export const PORT_STATE_BG: Record<PortState, string> = {
  'open': 'bg-green-500/10 text-green-400 border-green-500/20',
  'closed': 'bg-red-500/10 text-red-400 border-red-500/20',
  'filtered': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  'open|filtered': 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  'closed|filtered': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
};

export const HOST_STATE_COLORS: Record<HostState, string> = {
  'up': '#00ff88',
  'down': '#ff4444',
  'unknown': '#64748b',
  'skipped': '#64748b',
};

export const SERVICE_COLORS: string[] = [
  '#00d4ff',
  '#00ff88',
  '#a855f7',
  '#ff6b35',
  '#ffd700',
  '#ff4444',
  '#06b6d4',
  '#84cc16',
  '#f43f5e',
  '#8b5cf6',
];

export function getServiceColor(index: number): string {
  return SERVICE_COLORS[index % SERVICE_COLORS.length];
}

// OS icon/color mapping
export const OS_COLORS: Record<string, string> = {
  'Windows': '#00adef',
  'Linux': '#ffd700',
  'macOS': '#a8b2c1',
  'BSD': '#ab3434',
  'Cisco IOS': '#1ba0d7',
  'Android': '#3ddc84',
  'iOS': '#147efb',
  'Solaris': '#c73225',
  'Unknown': '#64748b',
};

export function getOsColor(os: string): string {
  return OS_COLORS[os] ?? '#64748b';
}
