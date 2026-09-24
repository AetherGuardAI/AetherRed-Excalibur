import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getCampaign } from '../services/api';
import { Clock, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

export default function Results() {
  const { id } = useParams<{ id: string }>();
  const { data: campaign, isLoading } = useQuery({
    queryKey: ['campaign', id],
    queryFn: () => getCampaign(id!),
    enabled: !!id,
    refetchInterval: (data: any) => data?.status === 'running' ? 3000 : false,
  });

  if (isLoading) return <div style={{ padding: '3rem', textAlign: 'center' }}><div className="spinner" /></div>;
  if (!campaign) return (
    <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
      <p style={{ color: 'var(--text-2)' }}>No campaign selected. Run a campaign first.</p>
    </div>
  );

  const result = campaign.result;
  const score = result?.resilience_score;

  const scoreColor = score
    ? score.overall >= 80 ? '#10b981' : score.overall >= 60 ? '#f59e0b' : '#ef4444'
    : 'var(--text-3)';

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 className="page-title">{campaign.name}</h1>
        <p className="page-sub">
          Status: <span style={{ color: campaign.status === 'completed' ? '#10b981' : campaign.status === 'running' ? '#f59e0b' : 'var(--text-2)', fontWeight: 600 }}>
            {campaign.status}
          </span>
        </p>
      </div>

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Score + Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.5rem' }}>
            {/* Resilience Score */}
            {score && (
              <div className="card" style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                  Resilience Score
                </div>
                <div style={{ fontSize: '3.5rem', fontWeight: 800, color: scoreColor, lineHeight: 1 }}>
                  {score.overall}
                </div>
                <div style={{ fontSize: '1.25rem', fontWeight: 600, color: scoreColor, marginTop: '0.5rem' }}>
                  Grade: {score.grade}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '0.5rem' }}>
                  AetherGuard Proprietary Score
                </div>
              </div>
            )}

            {/* Summary Stats */}
            <div className="grid-stats" style={{ marginBottom: 0 }}>
              <div className="stat-card" style={{ '--accent': '#3b82f6' } as any}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Attacks</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, marginTop: '0.375rem' }}>{result.total_attacks}</div>
              </div>
              <div className="stat-card" style={{ '--accent': '#10b981' } as any}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Completed</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, marginTop: '0.375rem' }}>{result.completed}</div>
              </div>
              <div className="stat-card" style={{ '--accent': '#f59e0b' } as any}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Attack Success Rate</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, marginTop: '0.375rem' }}>{(result.overall_success_rate * 100).toFixed(0)}%</div>
              </div>
              <div className="stat-card" style={{ '--accent': 'var(--purple)' } as any}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Duration</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, marginTop: '0.375rem' }}>{result.duration_seconds?.toFixed(1)}s</div>
              </div>
            </div>
          </div>

          {/* Attack Results Table */}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Attack</th>
                  <th>Category</th>
                  <th>ATLAS ID</th>
                  <th>Success Rate</th>
                  <th>Payloads</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {result.attack_results?.map((r: any, i: number) => {
                  const rateColor = r.success_rate > 0.5 ? '#ef4444' : r.success_rate > 0.1 ? '#f59e0b' : '#10b981';
                  const StatusIcon = r.status === 'success' || r.status === 'failure' ? CheckCircle : r.status === 'error' ? XCircle : Clock;
                  return (
                    <tr key={i}>
                      <td style={{ fontWeight: 500 }}>{r.attack_name}</td>
                      <td style={{ color: 'var(--text-2)' }}>{r.category}</td>
                      <td><code style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{r.atlas_id}</code></td>
                      <td><span style={{ color: rateColor, fontWeight: 700 }}>{(r.success_rate * 100).toFixed(0)}%</span></td>
                      <td style={{ color: 'var(--text-2)' }}>{r.payloads_successful}/{r.payloads_used}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                          <StatusIcon size={14} color={r.status === 'error' ? '#ef4444' : '#10b981'} />
                          <span style={{ fontSize: '0.8rem', color: 'var(--text-2)', textTransform: 'capitalize' }}>{r.status}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
