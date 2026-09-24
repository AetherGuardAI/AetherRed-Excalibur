import { Outlet, Link, useLocation } from 'react-router-dom';
import { Sword, LayoutDashboard, PlusCircle, Library, Settings, BarChart3 } from 'lucide-react';
import logo from '../assets/logo.png';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/campaigns/new', label: 'New Campaign', icon: PlusCircle },
  { path: '/attacks', label: 'Attack Library', icon: Library },
  { path: '/results', label: 'Results', icon: BarChart3 },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Layout() {
  const location = useLocation();

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg-base)', overflow: 'hidden' }}>
      {/* Sidebar */}
      <aside style={{
        width: '230px',
        flexShrink: 0,
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
      }}>
        {/* Brand */}
        <div style={{
          padding: '1.375rem 1.25rem 1.125rem',
          borderBottom: '1px solid var(--border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <img src={logo} alt="AetherGuard" style={{ width: '34px', height: '34px', objectFit: 'contain', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.01em' }}>
                Excalibur™
              </div>
              <div style={{ fontSize: '0.62rem', color: 'var(--text-3)', letterSpacing: '0.05em' }}>
                AetherRed • Red Team
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-2)', marginTop: '0.625rem', letterSpacing: '0.01em' }}>
            Attack your AI before attackers do.
          </div>
        </div>
        

        {/* Nav */}
        <nav style={{ flex: 1, padding: '0.75rem 0.625rem', display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0.75rem 0.75rem 0.5rem' }}>
            Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.625rem',
                  padding: '0.625rem 0.75rem',
                  color: isActive ? '#fff' : 'var(--text-2)',
                  background: isActive
                    ? 'linear-gradient(90deg, rgba(139,92,246,0.2), rgba(139,92,246,0.06))'
                    : 'transparent',
                  borderRadius: '0.5rem',
                  border: isActive ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                  fontSize: '0.8125rem',
                  fontWeight: isActive ? 600 : 400,
                  transition: 'all 0.15s',
                  textDecoration: 'none',
                }}
              >
                <Icon size={16} style={{ flexShrink: 0, color: isActive ? '#a78bfa' : 'inherit' }} />
                <span>{item.label}</span>
                {isActive && (
                  <span style={{
                    marginLeft: 'auto',
                    width: '6px', height: '6px',
                    borderRadius: '50%',
                    background: 'var(--purple)',
                    flexShrink: 0,
                  }} />
                )}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>v1.0.0 • AetherGuard AI</div>
        </div>
      </aside>

      {/* Main */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        {/* Top Bar */}
        <header style={{
          background: 'var(--bg-sidebar)',
          borderBottom: '1px solid var(--border)',
          padding: '0 1.5rem',
          height: '52px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-2)' }}>
            AI Red-Teaming & Attack Simulation Platform 
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '0.4rem',
              padding: '0.2rem 0.65rem',
              background: 'rgba(16,185,129,0.1)',
              border: '1px solid rgba(16,185,129,0.2)',
              borderRadius: '2rem',
            }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 500 }}>Ready</span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>
              16 attacks loaded
            </span>
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, overflow: 'auto', padding: '2rem' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
