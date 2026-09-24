import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { getAttacks, getCategories } from '../services/api';
import { ExternalLink } from 'lucide-react';

const categoryColors: Record<string, string> = {
  adversarial_ml: '#ef4444',
  nlp_language: '#3b82f6',
  agent_trust: '#8b5cf6',
  rag_embedding: '#10b981',
  infrastructure: '#f59e0b',
  model_integrity: '#f97316',
  evasion: '#06b6d4',
};

const categoryLabels: Record<string, string> = {
  adversarial_ml: 'Adversarial ML',
  nlp_language: 'NLP & Language',
  agent_trust: 'Agent & Trust',
  rag_embedding: 'RAG & Embedding',
  infrastructure: 'Infrastructure',
  model_integrity: 'Model Integrity',
  evasion: 'Evasion',
};

export default function AttackLibrary() {
  const [filter, setFilter] = useState<string | undefined>();
  const { data: attacks, isLoading } = useQuery({ queryKey: ['attacks', filter], queryFn: () => getAttacks(filter) });
  const { data: categories } = useQuery({ queryKey: ['categories'], queryFn: getCategories });

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 className="page-title">Attack Library</h1>
        <p className="page-sub">16 attack simulations across 7 categories — all MITRE ATLAS mapped</p>
      </div>

      {/* Category Filter */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <button
          onClick={() => setFilter(undefined)}
          className={!filter ? 'btn btn-primary' : 'btn btn-ghost'}
          style={{ fontSize: '0.8rem', padding: '0.375rem 0.875rem' }}
        >
          All ({attacks?.length ?? 0})
        </button>
        {categories?.map((cat: string) => {
          const color = categoryColors[cat] || '#6b7280';
          return (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                padding: '0.375rem 0.875rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem',
                cursor: 'pointer',
                border: filter === cat ? `1px solid ${color}` : '1px solid var(--border)',
                background: filter === cat ? `${color}15` : 'transparent',
                color: filter === cat ? color : 'var(--text-2)',
                transition: 'all 0.15s',
              }}
            >
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }} />
              {categoryLabels[cat] || cat}
            </button>
          );
        })}
      </div>

      {/* Attack Grid */}
      {isLoading ? (
        <div style={{ padding: '3rem', textAlign: 'center' }}><div className="spinner" /></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1rem' }}>
          {attacks?.map((attack: any) => {
            const color = categoryColors[attack.category] || '#6b7280';
            return (
              <div key={attack.name} className="card" style={{ padding: '1.25rem', transition: 'border-color 0.15s' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-1)', marginBottom: '0.25rem' }}>
                      {attack.display_name}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="badge" style={{ background: `${color}15`, color, border: `1px solid ${color}30` }}>
                        {attack.interface}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{attack.atlas_id}</span>
                    </div>
                  </div>
                  <a
                    href={`https://atlas.mitre.org/techniques/${attack.atlas_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: 'var(--text-3)', transition: 'color 0.15s' }}
                    title="View on MITRE ATLAS"
                  >
                    <ExternalLink size={14} />
                  </a>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-2)', lineHeight: 1.5 }}>
                  {attack.description}
                </p>
                <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{categoryLabels[attack.category] || attack.category}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
