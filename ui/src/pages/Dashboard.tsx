import { useQuery } from '@tanstack/react-query';
import { Sword, Shield, AlertTriangle, Activity, Target, Zap } from 'lucide-react';
import { getAttacks } from '../services/api';

export default function Dashboard() {
  const { data: attacks } = useQuery({ queryKey: ['attacks'], queryFn: () => getAttacks() });

  const stats = [
    { label: 'Attack Types', value: attacks?.length ?? 16, icon: Sword, color: '#8b5cf6' },
    { label: 'Categories', value: '7', icon: Shield, color: '#3b82f6' },
    { label: 'ATLAS Mapped', value: attacks?.length ?? 16, icon: Target, color: '#f59e0b' },
    { label: 'Interfaces', value: '3', icon: Activity, color: '#10b981', sub: 'CLI • API • UI' },
  ];

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 className="page-title">Dashboard</h1>
        <p className="page-sub">AetherRed — Excalibur attack simulation overview</p>
      </div>

      {/* Stats */}
      <div className="grid-stats">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="stat-card" style={{ '--accent': stat.color } as any}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                    {stat.label}
                  </div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-1)' }}>
                    {stat.value}
                  </div>
                  {stat.sub && <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>{stat.sub}</div>}
                </div>
                <div style={{
                  padding: '0.625rem',
                  borderRadius: '0.5rem',
                  background: `${stat.color}15`,
                  border: `1px solid ${stat.color}30`,
                }}>
                  <Icon size={20} color={stat.color} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Quick Actions */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '1rem' }}>Quick Actions</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
          <a href="/campaigns/new" style={{
            display: 'block', padding: '1.25rem',
            background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.2)',
            borderRadius: 'var(--radius)', transition: 'all 0.15s',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <Zap size={16} color="#a78bfa" />
              <span style={{ fontWeight: 600, color: 'var(--text-1)', fontSize: '0.875rem' }}>New Campaign</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-2)', lineHeight: 1.4 }}>
              Run a full attack campaign against a target LLM or agent
            </p>
          </a>

          <a href="/attacks" style={{
            display: 'block', padding: '1.25rem',
            background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.2)',
            borderRadius: 'var(--radius)', transition: 'all 0.15s',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <Shield size={16} color="#60a5fa" />
              <span style={{ fontWeight: 600, color: 'var(--text-1)', fontSize: '0.875rem' }}>Attack Library</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-2)', lineHeight: 1.4 }}>
              Browse all 16 attack types with MITRE ATLAS mapping
            </p>
          </a>

          <a href="/settings" style={{
            display: 'block', padding: '1.25rem',
            background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)',
            borderRadius: 'var(--radius)', transition: 'all 0.15s',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <Activity size={16} color="#34d399" />
              <span style={{ fontWeight: 600, color: 'var(--text-1)', fontSize: '0.875rem' }}>API Server</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-2)', lineHeight: 1.4 }}>
              Configure targets, credentials, and start the REST API
            </p>
          </a>
        </div>
      </div>

      {/* Attack Categories Overview */}
      <div className="card">
        <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '1rem' }}>Attack Categories</div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Attacks</th>
                <th>Interface</th>
                <th>Coverage</th>
              </tr>
            </thead>
            <tbody>
              {[
                { cat: 'Adversarial ML', count: 4, iface: 'White-box', color: '#ef4444' },
                { cat: 'NLP & Language', count: 3, iface: 'Black-box', color: '#3b82f6' },
                { cat: 'Agent & Trust', count: 2, iface: 'Protocol', color: '#8b5cf6' },
                { cat: 'RAG & Embedding', count: 3, iface: 'Vector + API', color: '#10b981' },
                { cat: 'Infrastructure', count: 2, iface: 'HTTP', color: '#f59e0b' },
                { cat: 'Model Integrity', count: 2, iface: 'Mixed', color: '#f97316' },
                { cat: 'Evasion', count: 1, iface: 'Black-box', color: '#06b6d4' },
              ].map(row => (
                <tr key={row.cat}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: row.color }} />
                      <span style={{ fontWeight: 500 }}>{row.cat}</span>
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-2)' }}>{row.count} attacks</td>
                  <td><span className="badge" style={{ background: `${row.color}15`, color: row.color, border: `1px solid ${row.color}30` }}>{row.iface}</span></td>
                  <td style={{ color: 'var(--text-2)' }}>ATLAS mapped</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
