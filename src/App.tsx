import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from '@/components/layout/Layout';
import { Dashboard } from '@/pages/Dashboard';
import { NetworkGraphPage } from '@/pages/NetworkGraphPage';
import { HostList } from '@/pages/HostList';
import { PortAnalysis } from '@/pages/PortAnalysis';
import { Services } from '@/pages/Services';
import { UploadPage } from '@/pages/UploadPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="graph" element={<NetworkGraphPage />} />
          <Route path="hosts" element={<HostList />} />
          <Route path="ports" element={<PortAnalysis />} />
          <Route path="services" element={<Services />} />
          <Route path="upload" element={<UploadPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
