import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import CampaignBuilder from './pages/CampaignBuilder';
import Results from './pages/Results';
import AttackLibrary from './pages/AttackLibrary';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/campaigns/new" element={<CampaignBuilder />} />
        <Route path="/campaigns/:id" element={<Results />} />
        <Route path="/results" element={<Results />} />
        <Route path="/attacks" element={<AttackLibrary />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
