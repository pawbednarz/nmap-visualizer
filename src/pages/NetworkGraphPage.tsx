import { NetworkGraph } from '@/components/graph/NetworkGraph';
import { HostDetail } from '@/components/host/HostDetail';
import { useHasScans } from '@/store/scanStore';

export function NetworkGraphPage() {
  const hasScans = useHasScans();

  if (!hasScans) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        No scan loaded.
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">
      <div className="flex-1 min-w-0">
        <NetworkGraph />
      </div>
      <HostDetail />
    </div>
  );
}
