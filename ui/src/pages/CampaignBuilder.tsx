import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Play, CheckCircle } from 'lucide-react';
import { getAttacks, createCampaign } from '../services/api';

const categoryColors: Record<string, string> = {
  adversarial_ml: '#ef4444',
  nlp_language: '#3b82f6',
  agent_trust: '#8b5cf6',
  rag_embedding: '#10b981',
  infrastructure: '#f59e0b',
  model_integrity: '#f97316',
  evasion: '#06b6d4',
};

export default function CampaignBuilder() {
  const { data: attacks } = useQuery({ queryKey: ['attacks'], queryFn: () => getAttacks() });
  const [name, setName] = useState('');
  const [targetType, setTargetType] = useState('openai');
  const [model, setModel] = useState('gpt-4o-mini');
  const [selectedAttacks, setSelectedAttacks] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const toggle = (n: string) => setSelectedAttacks(prev => prev.includes(n) ? prev.filter(a => a !== n) : [...prev, n]);

  const handleStart = async () => {
    if (!name || selectedAttacks.length === 0) return;
    setRunning(true);
    try {
      const res = await createCampaign({
        name,
        target: { type: targetType, model, api_key_env: `EXCALIBUR_${targetType.toUpperCase()}_API_KEY` },
        attacks: selectedAttacks.map(type => ({ type, enabled: true, params: { samples: 20 } })),
        parallel: 3,
        reporting: { formats: ['json', 'html'], resilience_score: true, atlas_mapping: true },
      });
      setResult(res);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 className="page-title">New Campaign</h1>
        <p className="page-sub">Configure and launch an attack campaign against a target</p>
      </div>

      {result ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <CheckCircle size={48} color="#10b981" style={{ margin: '0 auto 1rem' }} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-1)', marginBottom: '0.5rem' }}>Campaign Started</h2>
          <p style={{ color: 'var(--text-2)', marginBottom: '1.5rem' }}>ID: {result.id}</p>
          <a href={`/campaigns/${result.id}`} className="btn btn-primary">View Results</a>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Campaign Details */}
          <div className="card">
            <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '1.25rem' }}>Campaign Details</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <div>
                <label className="form-label">Campaign Name</label>
                <input value={name} onChange={e => setName(e.target.value)} placeholder="My Security Scan" className="input-field" />
              </div>
              <div>
                <label className="form-label">Target Type</label>
                <select value={targetType} onChange={e => setTargetType(e.target.value)} className="input-field">
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="azure">Azure OpenAI</option>
                  <option value="bedrock">AWS Bedrock</option>
                  <option value="local">Local (vLLM/TGI)</option>
                </select>
              </div>
              <div>
                <label className="form-label">Model</label>
                <input value={model} onChange={e => setModel(e.target.value)} className="input-field" />
              </div>
            </div>
          </div>

          {/* Attack Selection */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)' }}>Select Attacks</div>
              <span className="badge" style={{ background: 'rgba(139,92,246,0.15)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.3)' }}>
                {selectedAttacks.length} selected
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '0.75rem' }}>
              {attacks?.map((attack: any) => {
                const selected = selectedAttacks.includes(attack.name);
                const color = categoryColors[attack.category] || '#6b7280';
                return (
                  <button
                    key={attack.name}
                    onClick={() => toggle(attack.name)}
                    style={{
                      textAlign: 'left', padding: '0.875rem 1rem',
                      background: selected ? `${color}08` : 'var(--bg-deep)',
                      border: selected ? `1px solid ${color}50` : '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{
                        width: '16px', height: '16px', borderRadius: '3px',
                        border: selected ? `2px solid ${color}` : '2px solid var(--border-lt)',
                        background: selected ? color : 'transparent',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        flexShrink: 0,
                      }}>
                        {selected && <span style={{ color: '#fff', fontSize: '10px', fontWeight: 700 }}>✓</span>}
                      </span>
                      <span style={{ fontWeight: 500, fontSize: '0.8125rem', color: 'var(--text-1)' }}>{attack.display_name}</span>
                    </div>
                    <div style={{ marginTop: '0.375rem', paddingLeft: '1.5rem', fontSize: '0.7rem', color: 'var(--text-3)' }}>
                      {attack.atlas_id} • {attack.interface}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Start */}
          <button
            onClick={handleStart}
            disabled={running || !name || selectedAttacks.length === 0}
            className="btn btn-primary"
            style={{ alignSelf: 'flex-start', padding: '0.75rem 1.5rem', fontSize: '0.9rem' }}
          >
            <Play size={16} />
            {running ? 'Starting...' : 'Launch Campaign'}
          </button>
        </div>
      )}
    </div>
  );
}
