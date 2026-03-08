// ──────────────────────────────────────────────────────────────────────────────
// nmap data model – mirrors the nmap XML output schema
// ──────────────────────────────────────────────────────────────────────────────

export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered' | 'closed|filtered';
export type PortProtocol = 'tcp' | 'udp' | 'sctp' | 'ip';
export type HostState = 'up' | 'down' | 'unknown' | 'skipped';

// ── Port / Service ────────────────────────────────────────────────────────────

export interface NmapService {
  name: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  ostype?: string;
  method: string;
  conf: number;
  cpe?: string[];
}

export interface NmapScript {
  id: string;
  output: string;
  elements?: Record<string, string | string[]>;
}

export interface NmapPort {
  portid: number;
  protocol: PortProtocol;
  state: PortState;
  reason?: string;
  service?: NmapService;
  scripts?: NmapScript[];
}

// ── OS Detection ──────────────────────────────────────────────────────────────

export interface NmapOsClass {
  type?: string;
  vendor?: string;
  osfamily?: string;
  osgen?: string;
  accuracy: number;
  cpe?: string[];
}

export interface NmapOsMatch {
  name: string;
  accuracy: number;
  osClasses: NmapOsClass[];
}

export interface NmapOs {
  matches: NmapOsMatch[];
  portUsed?: {
    portid: number;
    protocol: PortProtocol;
    state: 'open' | 'closed';
  };
}

// ── Host ─────────────────────────────────────────────────────────────────────

export interface NmapAddress {
  addr: string;
  addrtype: 'ipv4' | 'ipv6' | 'mac';
  vendor?: string;
}

export interface NmapHostname {
  name: string;
  type: 'user' | 'PTR' | string;
}

export interface NmapTimings {
  starttime?: number;
  endtime?: number;
}

export interface NmapHost {
  id: string;                    // derived: primary IP
  state: HostState;
  reason?: string;
  addresses: NmapAddress[];
  hostnames: NmapHostname[];
  ports: NmapPort[];
  os?: NmapOs;
  scripts?: NmapScript[];
  timings: NmapTimings;

  // Computed helpers (populated by parser)
  ipv4?: string;
  ipv6?: string;
  mac?: string;
  macVendor?: string;
  displayName: string;           // hostname or IP
  openPorts: NmapPort[];
  openPortCount: number;
  topOs?: string;
}

// ── Scan ─────────────────────────────────────────────────────────────────────

export interface NmapScanStats {
  uphosts: number;
  downhosts: number;
  totalhosts: number;
  elapsed?: number;
}

export interface NmapRunStats {
  finished: {
    time: number;
    timestr: string;
    summary: string;
    elapsed: number;
    exit: string;
  };
  hosts: NmapScanStats;
}

export interface NmapScanInfo {
  type: string;
  protocol: string;
  numservices?: number;
  services?: string;
}

export interface NmapScan {
  // Scan metadata
  scanner: string;
  args: string;
  startTime: number;
  startStr: string;
  version: string;
  xmlOutputVersion: string;

  // Data
  scanInfo?: NmapScanInfo;
  hosts: NmapHost[];
  runStats: NmapRunStats;

  // Computed summary (populated by parser)
  totalHosts: number;
  upHosts: number;
  downHosts: number;
  totalOpenPorts: number;
  uniqueServices: string[];
  serviceDistribution: ServiceCount[];
  portDistribution: PortCount[];
  osDistribution: OsCount[];
}

// ── Aggregation helpers ───────────────────────────────────────────────────────

export interface ServiceCount {
  service: string;
  count: number;
}

export interface PortCount {
  port: number;
  service: string;
  count: number;
  protocol: PortProtocol;
}

export interface OsCount {
  os: string;
  count: number;
}

// ── UI state helpers ──────────────────────────────────────────────────────────

export interface HostFilter {
  search: string;
  state: HostState | 'all';
  minOpenPorts: number;
  service: string;
  os: string;
}
