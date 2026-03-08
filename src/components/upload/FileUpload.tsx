import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { UploadCloud, FileText, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { cn } from '@/lib/cn';
import { parseNmapFile } from '@/lib/parser';
import { useScanStore } from '@/store/scanStore';
import { Button } from '@/components/ui/Button';

type UploadState = 'idle' | 'dragging' | 'loading' | 'success' | 'error';

export function FileUpload() {
  const [uploadState, setUploadState] = useState<UploadState>('idle');
  const [errorMsg, setErrorMsg] = useState('');
  const [successInfo, setSuccessInfo] = useState('');
  const { loadScan } = useScanStore();
  const navigate = useNavigate();

  const processFile = useCallback(
    async (file: File) => {
      if (!file.name.endsWith('.xml')) {
        setErrorMsg('Only nmap XML files (.xml) are supported.');
        setUploadState('error');
        return;
      }

      setUploadState('loading');
      try {
        const scan = await parseNmapFile(file);
        loadScan(scan, file.name);
        setSuccessInfo(
          `${scan.upHosts} hosts up · ${scan.totalOpenPorts} open ports · ${scan.uniqueServices.length} services`
        );
        setUploadState('success');
        setTimeout(() => navigate('/'), 1200);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : 'Failed to parse file.');
        setUploadState('error');
      }
    },
    [loadScan, navigate]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const handleInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const reset = () => {
    setUploadState('idle');
    setErrorMsg('');
    setSuccessInfo('');
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Load nmap Scan</h2>
        <p className="text-sm text-slate-400">
          Upload an nmap XML output file generated with{' '}
          <code className="font-mono text-accent-cyan bg-surface-muted px-1 rounded">-oX</code> flag.
        </p>
      </div>

      {/* Drop zone */}
      <label
        className={cn(
          'relative flex flex-col items-center justify-center gap-4 p-12 rounded-2xl border-2 border-dashed transition-all duration-200 cursor-pointer',
          uploadState === 'dragging'
            ? 'border-accent-cyan bg-accent-cyan/5'
            : uploadState === 'success'
            ? 'border-accent-green bg-accent-green/5'
            : uploadState === 'error'
            ? 'border-accent-red bg-accent-red/5'
            : 'border-surface-border bg-surface-elevated hover:border-slate-500 hover:bg-surface-muted/50'
        )}
        onDragOver={(e) => {
          e.preventDefault();
          setUploadState('dragging');
        }}
        onDragLeave={() => setUploadState('idle')}
        onDrop={handleDrop}
      >
        <input
          type="file"
          accept=".xml"
          className="sr-only"
          onChange={handleInput}
          disabled={uploadState === 'loading'}
        />

        <AnimatePresence mode="wait">
          {uploadState === 'loading' && (
            <motion.div
              key="loading"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-3"
            >
              <Loader2 className="w-12 h-12 text-accent-cyan animate-spin" />
              <p className="text-sm text-slate-300">Parsing scan data…</p>
            </motion.div>
          )}

          {uploadState === 'success' && (
            <motion.div
              key="success"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-3 text-center"
            >
              <CheckCircle2 className="w-12 h-12 text-accent-green" />
              <p className="text-sm font-medium text-accent-green">Scan loaded successfully</p>
              <p className="text-xs text-slate-400 font-mono">{successInfo}</p>
            </motion.div>
          )}

          {uploadState === 'error' && (
            <motion.div
              key="error"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-3 text-center"
            >
              <AlertCircle className="w-12 h-12 text-accent-red" />
              <p className="text-sm font-medium text-red-400">{errorMsg}</p>
              <Button variant="secondary" size="sm" onClick={(e) => { e.preventDefault(); reset(); }}>
                Try again
              </Button>
            </motion.div>
          )}

          {(uploadState === 'idle' || uploadState === 'dragging') && (
            <motion.div
              key="idle"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-3 text-center pointer-events-none"
            >
              <div
                className={cn(
                  'w-16 h-16 rounded-2xl flex items-center justify-center transition-colors duration-200',
                  uploadState === 'dragging'
                    ? 'bg-accent-cyan/20'
                    : 'bg-surface-muted'
                )}
              >
                {uploadState === 'dragging' ? (
                  <UploadCloud className="w-8 h-8 text-accent-cyan" />
                ) : (
                  <FileText className="w-8 h-8 text-slate-400" />
                )}
              </div>
              <div>
                <p className="text-sm font-medium text-slate-200">
                  {uploadState === 'dragging' ? 'Drop to load scan' : 'Drop XML file here or click to browse'}
                </p>
                <p className="text-xs text-slate-500 mt-1">nmap -oX scan.xml target</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </label>

      {/* Example command */}
      <div className="glass-card p-4 space-y-2">
        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Example commands</p>
        {[
          'nmap -sV -sC -O -oX scan.xml 192.168.1.0/24',
          'nmap -p- -T4 -oX full_scan.xml 10.0.0.0/8',
          'nmap -sV --script vuln -oX vuln_scan.xml target.com',
        ].map((cmd) => (
          <code
            key={cmd}
            className="block text-xs font-mono text-accent-cyan bg-surface p-2 rounded-lg border border-surface-border"
          >
            {cmd}
          </code>
        ))}
      </div>
    </div>
  );
}
