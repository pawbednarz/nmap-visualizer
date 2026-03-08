import { useNavigate } from 'react-router-dom';
import { motion, type Variants } from 'framer-motion';
import {
  Server,
  Activity,
  Globe,
  ShieldAlert,
  UploadCloud,
  ArrowRight,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { useActiveScan, useHasScans } from '@/store/scanStore';
import { StatCard, Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { getServiceColor, getOsColor } from '@/lib/colors';

const ANIM_CONTAINER: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.07 } },
};

const ANIM_ITEM: Variants = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
};

// ──────────────────────────────────────────────────────────────────────────────
// Empty state
// ──────────────────────────────────────────────────────────────────────────────

function EmptyState() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 text-center py-24">
      <div className="w-20 h-20 rounded-2xl bg-surface-muted border border-surface-border flex items-center justify-center">
        <UploadCloud className="w-10 h-10 text-slate-500" />
      </div>
      <div>
        <h2 className="text-xl font-bold text-white mb-2">No scan loaded</h2>
        <p className="text-sm text-slate-400 max-w-sm">
          Load an nmap XML file to start visualizing your network scan results.
        </p>
      </div>
      <Button variant="primary" size="lg" onClick={() => navigate('/upload')}>
        <UploadCloud className="w-4 h-4" />
        Load Scan
      </Button>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Dashboard
// ──────────────────────────────────────────────────────────────────────────────

export function Dashboard() {
  const hasScans = useHasScans();
  const scan = useActiveScan();
  const navigate = useNavigate();

  if (!hasScans || !scan) {
    return <EmptyState />;
  }

  const topServices = scan.serviceDistribution.slice(0, 8);
  const topPorts = scan.portDistribution.slice(0, 10);
  const osData = scan.osDistribution.slice(0, 6);

  return (
    <motion.div
      variants={ANIM_CONTAINER}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Stat cards */}
      <motion.div variants={ANIM_ITEM} className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Hosts Up"
          value={scan.upHosts}
          icon={<Server className="w-4 h-4" />}
          color="text-accent-green"
          subtitle={`/ ${scan.totalHosts} total`}
        />
        <StatCard
          label="Open Ports"
          value={scan.totalOpenPorts}
          icon={<Activity className="w-4 h-4" />}
          color="text-accent-cyan"
        />
        <StatCard
          label="Services"
          value={scan.uniqueServices.length}
          icon={<Globe className="w-4 h-4" />}
          color="text-purple-400"
        />
        <StatCard
          label="Hosts Down"
          value={scan.downHosts}
          icon={<ShieldAlert className="w-4 h-4" />}
          color="text-accent-red"
        />
      </motion.div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Service distribution pie */}
        <motion.div variants={ANIM_ITEM}>
          <Card className="h-72">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Service Distribution</h3>
            {topServices.length === 0 ? (
              <p className="text-sm text-slate-500">No open ports found.</p>
            ) : (
              <ResponsiveContainer width="100%" height="85%">
                <PieChart>
                  <Pie
                    data={topServices}
                    dataKey="count"
                    nameKey="service"
                    cx="40%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {topServices.map((_, i) => (
                      <Cell key={i} fill={getServiceColor(i)} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#161b27',
                      border: '1px solid #1e2535',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#cbd5e1',
                    }}
                    formatter={(val, name) => [val, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </Card>
        </motion.div>

        {/* OS distribution */}
        <motion.div variants={ANIM_ITEM}>
          <Card className="h-72">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">OS Distribution</h3>
            {osData.length === 0 ? (
              <p className="text-sm text-slate-500">No OS detection data.</p>
            ) : (
              <div className="space-y-2.5 overflow-y-auto h-[calc(100%-2rem)]">
                {osData.map((item) => (
                  <div key={item.os} className="space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-300">{item.os}</span>
                      <span className="text-xs text-slate-400 font-mono">{item.count}</span>
                    </div>
                    <div className="h-1.5 bg-surface-muted rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${(item.count / scan.upHosts) * 100}%`,
                          background: getOsColor(item.os),
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </motion.div>

        {/* Top ports bar */}
        <motion.div variants={ANIM_ITEM}>
          <Card className="h-72">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Top Open Ports</h3>
            {topPorts.length === 0 ? (
              <p className="text-sm text-slate-500">No open ports found.</p>
            ) : (
              <ResponsiveContainer width="100%" height="85%">
                <BarChart
                  data={topPorts.slice(0, 8)}
                  margin={{ top: 0, right: 0, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2535" vertical={false} />
                  <XAxis
                    dataKey="port"
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#161b27',
                      border: '1px solid #1e2535',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#cbd5e1',
                    }}
                    formatter={(val, _, props) => [
                      val,
                      (props as { payload?: { service?: string } }).payload?.service ?? 'hosts',
                    ]}
                  />
                  <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} maxBarSize={32} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </Card>
        </motion.div>
      </div>

      {/* Recent hosts */}
      <motion.div variants={ANIM_ITEM}>
        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300">Live Hosts</h3>
            <Button variant="ghost" size="sm" onClick={() => navigate('/hosts')}>
              View all <ArrowRight className="w-3.5 h-3.5" />
            </Button>
          </div>
          <div className="divide-y divide-surface-border">
            {scan.hosts
              .filter((h) => h.state === 'up')
              .slice(0, 8)
              .map((host) => (
                <div
                  key={host.id}
                  className="flex items-center justify-between py-3 hover:bg-surface-muted/30 -mx-4 px-4 transition-colors cursor-pointer"
                  onClick={() => navigate('/hosts')}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-accent-green animate-pulse-slow shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-slate-200 font-mono">{host.displayName}</p>
                      {host.ipv4 && host.displayName !== host.ipv4 && (
                        <p className="text-xs text-slate-500 font-mono">{host.ipv4}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap justify-end">
                    {host.topOs && (
                      <Badge variant="muted">{host.topOs.split(' ').slice(0, 3).join(' ')}</Badge>
                    )}
                    <Badge variant="cyan">{host.openPortCount} ports</Badge>
                  </div>
                </div>
              ))}
          </div>
        </Card>
      </motion.div>

      {/* Scan info */}
      <motion.div variants={ANIM_ITEM}>
        <Card>
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Scan Details</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {[
              { label: 'Command', value: scan.args },
              { label: 'nmap Version', value: scan.version },
              { label: 'Scan Type', value: scan.scanInfo?.type ?? '—' },
              { label: 'Protocol', value: scan.scanInfo?.protocol ?? '—' },
              { label: 'Duration', value: `${scan.runStats.finished.elapsed}s` },
              { label: 'Total Hosts', value: String(scan.totalHosts) },
            ].map(({ label, value }) => (
              <div key={label} className="flex gap-2 text-sm">
                <span className="text-slate-500 shrink-0 w-28">{label}</span>
                <span className="text-slate-300 font-mono text-xs break-all">{value}</span>
              </div>
            ))}
          </div>
        </Card>
      </motion.div>
    </motion.div>
  );
}
