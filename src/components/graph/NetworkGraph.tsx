import { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  type Node,
  type Edge,
  type NodeProps,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { motion } from 'framer-motion';
import { useActiveScan, useScanStore } from '@/store/scanStore';
import type { NmapHost } from '@/types/nmap';
import { HOST_STATE_COLORS } from '@/lib/colors';

// ──────────────────────────────────────────────────────────────────────────────
// Custom node – Host
// ──────────────────────────────────────────────────────────────────────────────

function HostNode({ data }: NodeProps<{ host: NmapHost; selected: boolean }>) {
  const { host, selected } = data;
  const color = HOST_STATE_COLORS[host.state];

  return (
    <div
      className="relative flex flex-col items-center gap-1.5 cursor-pointer"
      style={{ width: 80 }}
    >
      {/* Glow ring */}
      <div
        className="absolute inset-0 rounded-full opacity-20 blur-lg"
        style={{ background: color }}
      />

      {/* Node circle */}
      <div
        className="w-14 h-14 rounded-full flex items-center justify-center border-2 transition-all duration-200 relative"
        style={{
          borderColor: selected ? color : `${color}44`,
          background: `${color}15`,
          boxShadow: selected ? `0 0 16px ${color}44` : 'none',
        }}
      >
        <div className="text-center">
          <div
            className="text-xs font-bold font-mono leading-none"
            style={{ color }}
          >
            {host.openPortCount}
          </div>
          <div className="text-[9px] text-slate-500 leading-none mt-0.5">ports</div>
        </div>
      </div>

      {/* Label */}
      <div className="text-center max-w-[90px]">
        <p className="text-[10px] font-mono text-slate-300 truncate leading-none">
          {host.displayName}
        </p>
        {host.topOs && (
          <p className="text-[9px] text-slate-500 truncate leading-none mt-0.5">
            {host.topOs.split(' ')[0]}
          </p>
        )}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Custom node – Gateway (centre)
// ──────────────────────────────────────────────────────────────────────────────

function GatewayNode() {
  return (
    <div className="flex flex-col items-center gap-1.5" style={{ width: 90 }}>
      <div className="w-16 h-16 rounded-full flex items-center justify-center border-2 border-accent-cyan bg-accent-cyan/10">
        <span className="text-[10px] font-mono text-accent-cyan font-bold">NETWORK</span>
      </div>
      <p className="text-[10px] font-mono text-accent-cyan">gateway</p>
    </div>
  );
}

const NODE_TYPES = {
  host: HostNode,
  gateway: GatewayNode,
};

// ──────────────────────────────────────────────────────────────────────────────
// Layout helpers – arrange hosts in circles around gateway
// ──────────────────────────────────────────────────────────────────────────────

function computeLayout(hosts: NmapHost[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  const GATEWAY_ID = '__gateway__';
  nodes.push({
    id: GATEWAY_ID,
    type: 'gateway',
    position: { x: 0, y: 0 },
    data: {},
    draggable: false,
  });

  const upHosts = hosts.filter((h) => h.state === 'up');
  const downHosts = hosts.filter((h) => h.state !== 'up');
  const allOrdered = [...upHosts, ...downHosts];

  const RING_CAPACITY = [8, 16, 24, 32];
  const RING_RADIUS = [180, 320, 460, 600];

  let hostIdx = 0;
  for (let ring = 0; ring < RING_CAPACITY.length && hostIdx < allOrdered.length; ring++) {
    const capacity = RING_CAPACITY[ring];
    const radius = RING_RADIUS[ring];
    const hostsInRing = allOrdered.slice(hostIdx, hostIdx + capacity);
    hostIdx += capacity;

    hostsInRing.forEach((host, i) => {
      const angle = (2 * Math.PI * i) / hostsInRing.length - Math.PI / 2;
      const x = Math.cos(angle) * radius;
      const y = Math.sin(angle) * radius;

      nodes.push({
        id: host.id,
        type: 'host',
        position: { x, y },
        data: { host, selected: false },
      });

      edges.push({
        id: `e-${GATEWAY_ID}-${host.id}`,
        source: GATEWAY_ID,
        target: host.id,
        style: {
          stroke: HOST_STATE_COLORS[host.state] + '44',
          strokeWidth: 1,
        },
        animated: host.state === 'up',
      });
    });
  }

  return { nodes, edges };
}

// ──────────────────────────────────────────────────────────────────────────────
// NetworkGraph page
// ──────────────────────────────────────────────────────────────────────────────

export function NetworkGraph() {
  const scan = useActiveScan();
  const { selectedHostId, selectHost } = useScanStore();

  const { nodes: baseNodes, edges } = useMemo(
    () => (scan ? computeLayout(scan.hosts) : { nodes: [], edges: [] }),
    [scan]
  );

  // Inject selected state into nodes
  const nodes = useMemo(
    () =>
      baseNodes.map((n) =>
        n.type === 'host'
          ? { ...n, data: { ...n.data, selected: n.id === selectedHostId } }
          : n
      ),
    [baseNodes, selectedHostId]
  );

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (node.type === 'host') {
        selectHost(node.id === selectedHostId ? null : node.id);
      }
    },
    [selectHost, selectedHostId]
  );

  if (!scan) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500">
        No scan loaded.
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="h-[calc(100vh-8rem)] rounded-xl overflow-hidden border border-surface-border"
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodeClick={onNodeClick}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={3}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#1e2535" />
        <Controls
          style={{ background: '#161b27', border: '1px solid #1e2535', borderRadius: '8px' }}
        />
        <MiniMap
          style={{ background: '#161b27', border: '1px solid #1e2535', borderRadius: '8px' }}
          nodeColor={(node) => {
            if (node.type === 'gateway') return '#00d4ff';
            const host = node.data?.host as NmapHost | undefined;
            return host ? HOST_STATE_COLORS[host.state] : '#64748b';
          }}
          maskColor="rgba(15,17,23,0.8)"
        />
      </ReactFlow>
    </motion.div>
  );
}
