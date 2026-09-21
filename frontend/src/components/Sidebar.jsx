import React from 'react';
import {
  LayoutDashboard,
  Radio,
  Cpu,
  ShieldCheck,
  Flame,
  FileText,
  Activity,
  Layers,
  Sparkles
} from 'lucide-react';

const Sidebar = ({ currentTab, onTabChange, stats = {} }) => {
  const navItems = [
    {
      id: 'dashboard',
      label: 'Security Dashboard',
      icon: LayoutDashboard,
      badge: null,
      desc: 'High-level posture & metrics'
    },
    {
      id: 'analyzer',
      label: 'Protocol Analyzer',
      icon: Radio,
      badge: stats.total_packets ? `${stats.total_packets}` : null,
      desc: 'Packet & SPI inspection'
    },
    {
      id: 'anomalies',
      label: 'ML Anomaly Detector',
      icon: Cpu,
      badge: stats.anomalies_detected ? `${stats.anomalies_detected}` : null,
      badgeColor: 'badge-warning',
      desc: 'Isolation & Random Forest'
    },
    {
      id: 'security',
      label: 'Security Assessment',
      icon: ShieldCheck,
      badge: stats.vulnerabilities_count ? `${stats.vulnerabilities_count}` : null,
      badgeColor: 'badge-danger',
      desc: 'Crypto & NIST compliance'
    },
    {
      id: 'simulator',
      label: 'Attack Simulator',
      icon: Flame,
      badge: '6 VECTORS',
      desc: 'Replay, downgrade, MITM'
    },
    {
      id: 'reports',
      label: 'AI Security Reports',
      icon: FileText,
      badge: 'AI GEN',
      desc: 'Executive & remediation'
    }
  ];

  return (
    <aside style={{
      width: 'var(--sidebar-width)',
      backgroundColor: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      height: 'calc(100vh - var(--header-height))',
      position: 'sticky',
      top: 'var(--header-height)',
      padding: '1.25rem 0.75rem',
      userSelect: 'none'
    }}>
      {/* Navigation Links */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
        <div style={{
          padding: '0 0.75rem 0.5rem',
          fontSize: '0.68rem',
          fontWeight: '700',
          letterSpacing: '0.1em',
          color: 'var(--text-muted)',
          textTransform: 'uppercase'
        }}>
          Core Modules
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                padding: '0.75rem 0.85rem',
                borderRadius: 'var(--radius-md)',
                border: isActive
                  ? '1px solid rgba(6, 182, 212, 0.4)'
                  : '1px solid transparent',
                backgroundColor: isActive
                  ? 'rgba(6, 182, 212, 0.12)'
                  : 'transparent',
                color: isActive ? 'var(--text-bright)' : 'var(--text-secondary)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all var(--transition-fast)',
                position: 'relative'
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.04)';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  filter: isActive ? 'drop-shadow(0 0 8px rgba(6, 182, 212, 0.6))' : 'none'
                }}>
                  <Icon size={18} />
                </div>
                <div>
                  <div style={{
                    fontSize: '0.85rem',
                    fontWeight: isActive ? '700' : '500',
                    lineHeight: 1.2
                  }}>
                    {item.label}
                  </div>
                  <div style={{
                    fontSize: '0.68rem',
                    color: 'var(--text-muted)',
                    marginTop: '2px'
                  }}>
                    {item.desc}
                  </div>
                </div>
              </div>

              {item.badge && (
                <span style={{
                  fontSize: '0.65rem',
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  backgroundColor: item.badgeColor === 'badge-danger'
                    ? 'rgba(239, 68, 68, 0.2)'
                    : item.badgeColor === 'badge-warning'
                    ? 'rgba(245, 158, 11, 0.2)'
                    : 'rgba(59, 130, 246, 0.2)',
                  color: item.badgeColor === 'badge-danger'
                    ? 'var(--accent-red)'
                    : item.badgeColor === 'badge-warning'
                    ? 'var(--accent-orange)'
                    : 'var(--accent-cyan)',
                  border: '1px solid currentColor'
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Telemetry Card */}
      <div style={{
        padding: '0.85rem',
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'var(--bg-tertiary)',
        border: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{
            fontSize: '0.7rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}>
            <Activity size={12} color="var(--accent-cyan)" /> PIPELINE STATUS
          </span>
          <span style={{
            fontSize: '0.65rem',
            color: 'var(--accent-green)',
            fontWeight: '600'
          }}>
            READY
          </span>
        </div>

        <div style={{
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.4
        }}>
          ML Models: <strong style={{ color: 'var(--accent-blue)' }}>Isolation Forest</strong> & <strong style={{ color: 'var(--accent-purple)' }}>RF Classifier</strong> active.
        </div>

        <div style={{
          display: 'flex',
          gap: '4px',
          height: '4px',
          borderRadius: '2px',
          overflow: 'hidden',
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          marginTop: '4px'
        }}>
          <div style={{ flex: 3, backgroundColor: 'var(--accent-cyan)' }} />
          <div style={{ flex: 2, backgroundColor: 'var(--accent-blue)' }} />
          <div style={{ flex: 1, backgroundColor: 'var(--accent-purple)' }} />
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
