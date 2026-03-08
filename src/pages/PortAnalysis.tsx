import { motion, type Variants } from 'framer-motion';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useActiveScan, useHasScans } from '@/store/scanStore';
import { Card } from '@/components/ui/Card';
import { Badge, PortStateBadge } from '@/components/ui/Badge';
import { getServiceColor } from '@/lib/colors';

const ANIM: Variants = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
};

const CONTAINER: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

export function PortAnalysis() {
  const hasScans = useHasScans();
  const scan = useActiveScan();

  if (!hasScans || !scan) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        No scan loaded.
      </div>
    );
  }

  const topPorts = scan.portDistribution.slice(0, 20);
  const topServices = scan.serviceDistribution.slice(0, 10);

  return (
    <motion.div variants={CONTAINER} initial="hidden" animate="show" className="space-y-6">
      {/* Top ports bar chart */}
      <motion.div variants={ANIM}>
        <Card className="p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-5">
            Top Open Ports — Host Count
          </h3>
          {topPorts.length === 0 ? (
            <p className="text-sm text-slate-500">No open ports found.</p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topPorts} margin={{ left: -10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2535" vertical={false} />
                <XAxis
                  dataKey="port"
                  tick={{ fontSize: 11, fill: '#64748b', fontFamily: 'monospace' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 11, fill: '#64748b' }}
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
                    `${val} hosts`,
                    `${(props as { payload?: { service?: string; protocol?: string } }).payload?.service ?? '?'} (${(props as { payload?: { service?: string; protocol?: string } }).payload?.protocol ?? '?'})`,
                  ]}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={36}>
                  {topPorts.map((_, i) => (
                    <Cell key={i} fill={getServiceColor(i)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </motion.div>

      {/* Service split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Service pie */}
        <motion.div variants={ANIM}>
          <Card className="p-5 h-72">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Service Mix</h3>
            {topServices.length === 0 ? (
              <p className="text-sm text-slate-500">No services detected.</p>
            ) : (
              <div className="flex items-center h-[85%]">
                <ResponsiveContainer width="55%" height="100%">
                  <PieChart>
                    <Pie
                      data={topServices}
                      dataKey="count"
                      nameKey="service"
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={3}
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
                    />
                  </PieChart>
                </ResponsiveContainer>

                {/* Legend */}
                <div className="flex-1 space-y-2 overflow-y-auto">
                  {topServices.map((item, i) => (
                    <div key={item.service} className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ background: getServiceColor(i) }}
                        />
                        <span className="text-xs text-slate-300 font-mono">{item.service}</span>
                      </div>
                      <span className="text-xs text-slate-500 font-mono">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </motion.div>

        {/* Port table */}
        <motion.div variants={ANIM}>
          <Card className="p-5 h-72 overflow-hidden flex flex-col">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Port Details</h3>
            <div className="overflow-y-auto flex-1">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-surface-border">
                    <th className="text-left pb-2 text-slate-400 font-medium">Port</th>
                    <th className="text-left pb-2 text-slate-400 font-medium">Proto</th>
                    <th className="text-left pb-2 text-slate-400 font-medium">Service</th>
                    <th className="text-right pb-2 text-slate-400 font-medium">Hosts</th>
                  </tr>
                </thead>
                <tbody>
                  {topPorts.map((p, i) => (
                    <tr
                      key={`${p.port}/${p.protocol}`}
                      className="border-b border-surface-border/40"
                    >
                      <td className="py-2 font-mono text-slate-200">{p.port}</td>
                      <td className="py-2">
                        <Badge variant="muted">{p.protocol}</Badge>
                      </td>
                      <td className="py-2">
                        <span style={{ color: getServiceColor(i) }} className="font-mono">
                          {p.service}
                        </span>
                      </td>
                      <td className="py-2 text-right font-mono text-slate-300">{p.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </motion.div>
      </div>

      {/* All open ports per host heatmap-style */}
      <motion.div variants={ANIM}>
        <Card className="p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Open Port States Distribution</h3>
          <div className="space-y-2">
            {scan.hosts
              .filter((h) => h.state === 'up' && h.ports.length > 0)
              .slice(0, 30)
              .map((host) => (
                <div key={host.id} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400 w-36 truncate shrink-0">
                    {host.displayName}
                  </span>
                  <div className="flex flex-wrap gap-0.5 flex-1">
                    {host.ports.slice(0, 40).map((port) => (
                      <PortStateBadge
                        key={`${port.portid}/${port.protocol}`}
                        state={port.state}
                      />
                    ))}
                    {host.ports.length > 40 && (
                      <Badge variant="muted">+{host.ports.length - 40}</Badge>
                    )}
                  </div>
                </div>
              ))}
          </div>
        </Card>
      </motion.div>
    </motion.div>
  );
}
