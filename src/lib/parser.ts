import { XMLParser } from 'fast-xml-parser';
import type {
  NmapScan,
  NmapHost,
  NmapPort,
  NmapAddress,
  NmapHostname,
  NmapOsMatch,
  NmapScript,
  NmapService,
  PortState,
  PortProtocol,
  HostState,
  ServiceCount,
  PortCount,
  OsCount,
} from '@/types/nmap';

// ──────────────────────────────────────────────────────────────────────────────
// XML Parser configuration
// ──────────────────────────────────────────────────────────────────────────────

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (tagName) =>
    ['host', 'port', 'address', 'hostname', 'osmatch', 'osclass', 'script', 'cpe'].includes(tagName),
  parseAttributeValue: true,
});

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function ensureArray<T>(val: T | T[] | undefined): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

function attr(obj: Record<string, unknown>, key: string): string {
  return String(obj[`@_${key}`] ?? '');
}

function numAttr(obj: Record<string, unknown>, key: string): number {
  return Number(obj[`@_${key}`] ?? 0);
}

// ──────────────────────────────────────────────────────────────────────────────
// Script parsing
// ──────────────────────────────────────────────────────────────────────────────

function parseScript(raw: Record<string, unknown>): NmapScript {
  return {
    id: attr(raw, 'id'),
    output: attr(raw, 'output'),
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Service parsing
// ──────────────────────────────────────────────────────────────────────────────

function parseService(raw: Record<string, unknown>): NmapService {
  const cpeRaw = ensureArray(raw['cpe'] as string[] | undefined);
  return {
    name: attr(raw, 'name'),
    product: attr(raw, 'product') || undefined,
    version: attr(raw, 'version') || undefined,
    extrainfo: attr(raw, 'extrainfo') || undefined,
    ostype: attr(raw, 'ostype') || undefined,
    method: attr(raw, 'method'),
    conf: numAttr(raw, 'conf'),
    cpe: cpeRaw.length ? cpeRaw.map(String) : undefined,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Port parsing
// ──────────────────────────────────────────────────────────────────────────────

function parsePort(raw: Record<string, unknown>): NmapPort {
  const stateRaw = raw['state'] as Record<string, unknown> | undefined;
  const serviceRaw = raw['service'] as Record<string, unknown> | undefined;
  const scriptsRaw = ensureArray(raw['script'] as Record<string, unknown>[] | undefined);

  return {
    portid: numAttr(raw, 'portid'),
    protocol: attr(raw, 'protocol') as PortProtocol,
    state: (stateRaw ? attr(stateRaw, 'state') : 'filtered') as PortState,
    reason: stateRaw ? attr(stateRaw, 'reason') : undefined,
    service: serviceRaw ? parseService(serviceRaw) : undefined,
    scripts: scriptsRaw.length ? scriptsRaw.map((s) => parseScript(s)) : undefined,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// OS parsing
// ──────────────────────────────────────────────────────────────────────────────

function parseOs(raw: Record<string, unknown>) {
  const matchesRaw = ensureArray(raw['osmatch'] as Record<string, unknown>[] | undefined);
  const portUsedRaw = raw['portused'] as Record<string, unknown> | undefined;

  const matches: NmapOsMatch[] = matchesRaw.map((m) => {
    const classesRaw = ensureArray(m['osclass'] as Record<string, unknown>[] | undefined);
    return {
      name: attr(m, 'name'),
      accuracy: numAttr(m, 'accuracy'),
      osClasses: classesRaw.map((c) => ({
        type: attr(c, 'type') || undefined,
        vendor: attr(c, 'vendor') || undefined,
        osfamily: attr(c, 'osfamily') || undefined,
        osgen: attr(c, 'osgen') || undefined,
        accuracy: numAttr(c, 'accuracy'),
        cpe: ensureArray(c['cpe'] as string[] | undefined).map(String),
      })),
    };
  });

  return {
    matches,
    portUsed: portUsedRaw
      ? {
          portid: numAttr(portUsedRaw, 'portid'),
          protocol: attr(portUsedRaw, 'proto') as 'tcp' | 'udp',
          state: attr(portUsedRaw, 'state') as 'open' | 'closed',
        }
      : undefined,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Host parsing
// ──────────────────────────────────────────────────────────────────────────────

function parseHost(raw: Record<string, unknown>): NmapHost {
  const statusRaw = raw['status'] as Record<string, unknown> | undefined;
  const addressesRaw = ensureArray(raw['address'] as Record<string, unknown>[] | undefined);
  const hostnamesContainer = raw['hostnames'] as Record<string, unknown> | undefined;
  const hostnamesRaw = hostnamesContainer
    ? ensureArray(hostnamesContainer['hostname'] as Record<string, unknown>[] | undefined)
    : [];
  const portsContainer = raw['ports'] as Record<string, unknown> | undefined;
  const portsRaw = portsContainer
    ? ensureArray(portsContainer['port'] as Record<string, unknown>[] | undefined)
    : [];
  const osRaw = raw['os'] as Record<string, unknown> | undefined;
  const scriptsRaw = (() => {
    const hsc = raw['hostscript'] as Record<string, unknown> | undefined;
    return hsc ? ensureArray(hsc['script'] as Record<string, unknown>[] | undefined) : [];
  })();
  const timesRaw = raw['times'] as Record<string, unknown> | undefined;

  const addresses: NmapAddress[] = addressesRaw.map((a) => ({
    addr: attr(a, 'addr'),
    addrtype: attr(a, 'addrtype') as NmapAddress['addrtype'],
    vendor: attr(a, 'vendor') || undefined,
  }));

  const hostnames: NmapHostname[] = hostnamesRaw.map((h) => ({
    name: attr(h, 'name'),
    type: attr(h, 'type'),
  }));

  const ports: NmapPort[] = portsRaw.map(parsePort);
  const openPorts = ports.filter((p) => p.state === 'open');

  const ipv4 = addresses.find((a) => a.addrtype === 'ipv4')?.addr;
  const ipv6 = addresses.find((a) => a.addrtype === 'ipv6')?.addr;
  const macAddr = addresses.find((a) => a.addrtype === 'mac');
  const primaryIp = ipv4 ?? ipv6 ?? addresses[0]?.addr ?? 'unknown';

  const displayName =
    hostnames.find((h) => h.type === 'PTR')?.name ??
    hostnames[0]?.name ??
    primaryIp;

  const os = osRaw ? parseOs(osRaw) : undefined;
  const topOs = os?.matches.sort((a, b) => b.accuracy - a.accuracy)[0]?.name;

  return {
    id: primaryIp,
    state: (statusRaw ? attr(statusRaw, 'state') : 'unknown') as HostState,
    reason: statusRaw ? attr(statusRaw, 'reason') : undefined,
    addresses,
    hostnames,
    ports,
    os,
    scripts: scriptsRaw.length ? scriptsRaw.map(parseScript) : undefined,
    timings: {
      starttime: timesRaw ? numAttr(timesRaw, 'starttime') : undefined,
      endtime: timesRaw ? numAttr(timesRaw, 'endtime') : undefined,
    },
    ipv4,
    ipv6,
    mac: macAddr?.addr,
    macVendor: macAddr?.vendor,
    displayName,
    openPorts,
    openPortCount: openPorts.length,
    topOs,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Aggregation
// ──────────────────────────────────────────────────────────────────────────────

function computeServiceDistribution(hosts: NmapHost[]): ServiceCount[] {
  const map = new Map<string, number>();
  for (const host of hosts) {
    for (const port of host.openPorts) {
      const name = port.service?.name ?? 'unknown';
      map.set(name, (map.get(name) ?? 0) + 1);
    }
  }
  return Array.from(map.entries())
    .map(([service, count]) => ({ service, count }))
    .sort((a, b) => b.count - a.count);
}

function computePortDistribution(hosts: NmapHost[]): PortCount[] {
  const map = new Map<string, PortCount>();
  for (const host of hosts) {
    for (const port of host.openPorts) {
      const key = `${port.portid}/${port.protocol}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
      } else {
        map.set(key, {
          port: port.portid,
          service: port.service?.name ?? 'unknown',
          count: 1,
          protocol: port.protocol,
        });
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

function computeOsDistribution(hosts: NmapHost[]): OsCount[] {
  const map = new Map<string, number>();
  for (const host of hosts) {
    const topOs = host.topOs ?? 'Unknown';
    // Simplify OS name to family
    const family = simplifyOsName(topOs);
    map.set(family, (map.get(family) ?? 0) + 1);
  }
  return Array.from(map.entries())
    .map(([os, count]) => ({ os, count }))
    .sort((a, b) => b.count - a.count);
}

function simplifyOsName(name: string): string {
  if (/windows/i.test(name)) return 'Windows';
  if (/linux/i.test(name)) return 'Linux';
  if (/macos|os x|darwin/i.test(name)) return 'macOS';
  if (/bsd/i.test(name)) return 'BSD';
  if (/cisco/i.test(name)) return 'Cisco IOS';
  if (/android/i.test(name)) return 'Android';
  if (/ios/i.test(name)) return 'iOS';
  if (/solaris/i.test(name)) return 'Solaris';
  return name.split(' ').slice(0, 2).join(' ');
}

// ──────────────────────────────────────────────────────────────────────────────
// Main parse entry point
// ──────────────────────────────────────────────────────────────────────────────

export function parseNmapXml(xmlString: string): NmapScan {
  const parsed = xmlParser.parse(xmlString) as Record<string, unknown>;
  const root = parsed['nmaprun'] as Record<string, unknown>;

  if (!root) {
    throw new Error('Invalid nmap XML: missing <nmaprun> root element');
  }

  const hostsRaw = ensureArray(root['host'] as Record<string, unknown>[] | undefined);
  const hosts = hostsRaw.map(parseHost);

  const runStatsRaw = root['runstats'] as Record<string, unknown> | undefined;
  const finishedRaw = runStatsRaw?.['finished'] as Record<string, unknown> | undefined;
  const hostsStatsRaw = runStatsRaw?.['hosts'] as Record<string, unknown> | undefined;

  const runStats = {
    finished: {
      time: finishedRaw ? numAttr(finishedRaw, 'time') : 0,
      timestr: finishedRaw ? attr(finishedRaw, 'timestr') : '',
      summary: finishedRaw ? attr(finishedRaw, 'summary') : '',
      elapsed: finishedRaw ? numAttr(finishedRaw, 'elapsed') : 0,
      exit: finishedRaw ? attr(finishedRaw, 'exit') : '',
    },
    hosts: {
      uphosts: hostsStatsRaw ? numAttr(hostsStatsRaw, 'up') : 0,
      downhosts: hostsStatsRaw ? numAttr(hostsStatsRaw, 'down') : 0,
      totalhosts: hostsStatsRaw ? numAttr(hostsStatsRaw, 'total') : 0,
    },
  };

  const scanInfoRaw = root['scaninfo'] as Record<string, unknown> | undefined;

  const upHosts = hosts.filter((h) => h.state === 'up');
  const serviceDistribution = computeServiceDistribution(upHosts);
  const portDistribution = computePortDistribution(upHosts);
  const osDistribution = computeOsDistribution(upHosts.filter((h) => h.topOs));
  const uniqueServices = [...new Set(serviceDistribution.map((s) => s.service))];
  const totalOpenPorts = upHosts.reduce((sum, h) => sum + h.openPortCount, 0);

  return {
    scanner: attr(root, 'scanner'),
    args: attr(root, 'args'),
    startTime: numAttr(root, 'start'),
    startStr: attr(root, 'startstr'),
    version: attr(root, 'version'),
    xmlOutputVersion: attr(root, 'xmloutputversion'),
    scanInfo: scanInfoRaw
      ? {
          type: attr(scanInfoRaw, 'type'),
          protocol: attr(scanInfoRaw, 'protocol'),
          numservices: numAttr(scanInfoRaw, 'numservices') || undefined,
          services: attr(scanInfoRaw, 'services') || undefined,
        }
      : undefined,
    hosts,
    runStats,
    totalHosts: hosts.length,
    upHosts: upHosts.length,
    downHosts: hosts.filter((h) => h.state === 'down').length,
    totalOpenPorts,
    uniqueServices,
    serviceDistribution,
    portDistribution,
    osDistribution,
  };
}

export async function parseNmapFile(file: File): Promise<NmapScan> {
  const text = await file.text();
  return parseNmapXml(text);
}
