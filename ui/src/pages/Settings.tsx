import { Shield, Terminal, Info } from 'lucide-react';

export default function Settings() {
  return (
    <div className="fade-up">
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 className="page-title">Settings</h1>
        <p className="page-sub">Configure targets, credentials, and server options</p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Target Configuration */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <Shield size={18} color="var(--purple)" />
            <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)' }}>Target Configuration</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-2)', marginBottom: '1rem', lineHeight: 1.5 }}>
            API keys are read from environment variables. Set these before running attacks:
          </p>
          <div className="card-deep" style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: '0.8rem', lineHeight: 1.8 }}>
            <div style={{ color: 'var(--text-2)' }}>
              <span style={{ color: '#10b981' }}>EXCALIBUR_OPENAI_API_KEY</span>=sk-...<br />
              <span style={{ color: '#10b981' }}>EXCALIBUR_ANTHROPIC_API_KEY</span>=sk-ant-...<br />
              <span style={{ color: '#10b981' }}>EXCALIBUR_AZURE_OPENAI_API_KEY</span>=...<br />
              <span style={{ color: '#10b981' }}>AWS_REGION</span>=us-east-1 <span style={{ color: 'var(--text-3)' }}># for Bedrock</span>
            </div>
          </div>
        </div>

        {/* API Server */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <Terminal size={18} color="var(--blue)" />
            <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)' }}>API Server</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-2)', marginBottom: '1rem' }}>
            The Excalibur REST API server provides programmatic access to all attack capabilities.
          </p>
          <div className="card-deep" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem' }}>
            <span style={{ color: 'var(--text-3)' }}>$ </span>
            <span style={{ color: '#10b981' }}>excalibur serve</span> --port 8100
          </div>
          <div style={{ marginTop: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--green)' }} />
              Swagger: http://localhost:8100/docs
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--blue)' }} />
              Health: http://localhost:8100/health
            </div>
          </div>
        </div>

        {/* About */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <Info size={18} color="var(--text-3)" />
            <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-1)' }}>About</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.5rem 1.5rem', fontSize: '0.8125rem' }}>
            <span style={{ color: 'var(--text-3)' }}>Product</span>
            <span style={{ color: 'var(--text-1)' }}>AetherRed — Excalibur</span>
            <span style={{ color: 'var(--text-3)' }}>Version</span>
            <span style={{ color: 'var(--text-1)' }}>1.0.0</span>
            <span style={{ color: 'var(--text-3)' }}>Attacks</span>
            <span style={{ color: 'var(--text-1)' }}>16 types • 7 categories</span>
            <span style={{ color: 'var(--text-3)' }}>Scoring</span>
            <span style={{ color: 'var(--text-1)' }}>MITRE ATLAS + ART + Resilience Score</span>
            <span style={{ color: 'var(--text-3)' }}>Organization</span>
            <span style={{ color: 'var(--text-1)' }}>AetherGuard AI</span>
          </div>
        </div>
      </div>
    </div>
  );
}
