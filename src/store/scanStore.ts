import { create } from 'zustand';
import type { NmapScan, NmapHost, HostFilter } from '@/types/nmap';

// ──────────────────────────────────────────────────────────────────────────────
// State shape
// ──────────────────────────────────────────────────────────────────────────────

interface ScanState {
  // Loaded scans (supports multiple scans)
  scans: NmapScan[];
  activeScanIndex: number;

  // UI state
  selectedHostId: string | null;
  filter: HostFilter;
  isLoading: boolean;
  error: string | null;

  // Derived (memoized on set)
  filteredHosts: NmapHost[];

  // Actions
  loadScan: (scan: NmapScan, filename?: string) => void;
  removeScan: (index: number) => void;
  setActiveScan: (index: number) => void;
  selectHost: (id: string | null) => void;
  setFilter: (partial: Partial<HostFilter>) => void;
  clearFilter: () => void;
  clearAll: () => void;
}

// ──────────────────────────────────────────────────────────────────────────────
// Defaults
// ──────────────────────────────────────────────────────────────────────────────

const DEFAULT_FILTER: HostFilter = {
  search: '',
  state: 'all',
  minOpenPorts: 0,
  service: '',
  os: '',
};

function applyFilter(hosts: NmapHost[], filter: HostFilter): NmapHost[] {
  return hosts.filter((host) => {
    // State
    if (filter.state !== 'all' && host.state !== filter.state) return false;

    // Min open ports
    if (host.openPortCount < filter.minOpenPorts) return false;

    // Search (IP, hostname, MAC)
    if (filter.search) {
      const q = filter.search.toLowerCase();
      const match =
        host.displayName.toLowerCase().includes(q) ||
        (host.ipv4?.includes(q) ?? false) ||
        (host.ipv6?.toLowerCase().includes(q) ?? false) ||
        (host.mac?.toLowerCase().includes(q) ?? false) ||
        host.hostnames.some((h) => h.name.toLowerCase().includes(q));
      if (!match) return false;
    }

    // Service filter
    if (filter.service) {
      const hasService = host.openPorts.some(
        (p) => p.service?.name?.toLowerCase() === filter.service.toLowerCase()
      );
      if (!hasService) return false;
    }

    // OS filter
    if (filter.os) {
      const osName = host.topOs ?? '';
      if (!osName.toLowerCase().includes(filter.os.toLowerCase())) return false;
    }

    return true;
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// Store
// ──────────────────────────────────────────────────────────────────────────────

export const useScanStore = create<ScanState>((set) => ({
  scans: [],
  activeScanIndex: 0,
  selectedHostId: null,
  filter: DEFAULT_FILTER,
  isLoading: false,
  error: null,
  filteredHosts: [],

  loadScan: (scan) => {
    set((state) => {
      const scans = [...state.scans, scan];
      const activeScanIndex = scans.length - 1;
      const filteredHosts = applyFilter(scan.hosts, state.filter);
      return { scans, activeScanIndex, filteredHosts, error: null };
    });
  },

  removeScan: (index) => {
    set((state) => {
      const scans = state.scans.filter((_, i) => i !== index);
      const activeScanIndex = Math.min(state.activeScanIndex, Math.max(0, scans.length - 1));
      const activeScan = scans[activeScanIndex];
      const filteredHosts = activeScan ? applyFilter(activeScan.hosts, state.filter) : [];
      return { scans, activeScanIndex, filteredHosts, selectedHostId: null };
    });
  },

  setActiveScan: (index) => {
    set((state) => {
      const activeScan = state.scans[index];
      const filteredHosts = activeScan ? applyFilter(activeScan.hosts, state.filter) : [];
      return { activeScanIndex: index, filteredHosts, selectedHostId: null };
    });
  },

  selectHost: (id) => set({ selectedHostId: id }),

  setFilter: (partial) => {
    set((state) => {
      const filter = { ...state.filter, ...partial };
      const activeScan = state.scans[state.activeScanIndex];
      const filteredHosts = activeScan ? applyFilter(activeScan.hosts, filter) : [];
      return { filter, filteredHosts };
    });
  },

  clearFilter: () => {
    set((state) => {
      const activeScan = state.scans[state.activeScanIndex];
      const filteredHosts = activeScan ? applyFilter(activeScan.hosts, DEFAULT_FILTER) : [];
      return { filter: DEFAULT_FILTER, filteredHosts };
    });
  },

  clearAll: () =>
    set({
      scans: [],
      activeScanIndex: 0,
      selectedHostId: null,
      filter: DEFAULT_FILTER,
      filteredHosts: [],
      error: null,
    }),
}));

// ──────────────────────────────────────────────────────────────────────────────
// Derived selectors
// ──────────────────────────────────────────────────────────────────────────────

export const useActiveScan = () =>
  useScanStore((state) => state.scans[state.activeScanIndex] ?? null);

export const useSelectedHost = () =>
  useScanStore((state) => {
    const scan = state.scans[state.activeScanIndex];
    if (!scan || !state.selectedHostId) return null;
    return scan.hosts.find((h) => h.id === state.selectedHostId) ?? null;
  });

export const useHasScans = () => useScanStore((state) => state.scans.length > 0);

