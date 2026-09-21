import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Cpu,
  Layers,
  FileText,
  AlertTriangle,
  ArrowRight,
  TrendingUp,
  Lock,
  Flame,
  Radio
} from 'lucide-react';
import SecurityGauge from '../components/SecurityGauge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

const Dashboard = ({
  stats,
  analysisData,
  securityData,
  mlData,
  loading,
  onNavigate
}) => {
  if (loading && !stats) {
    return <LoadingSpinner text="Compiling Security Telemetry..." />;
  }

  const score = securityData?.security_score ?? stats?.security_score ?? 78;
  const totalPackets = stats?.total_packets ?? analysisData?.summary?.total_packets ?? 0;
  const anomaliesCount = stats?.anomalies_detected ?? mlData?.anomalies_count ?? 0;
  const vulnsCount = stats?.vulnerabilities_count ?? securityData?.vulnerabilities?.length ?? 0;
  const activeSAs = stats?.active_sas_count ?? analysisData?.summary?.active_sas ?? 3;

  const protocolDist = analysisData?.summary?.protocol_distribution || {
    ESP: 72,
    IKEv2: 18,
    IKEv1: 6,
    AH: 4
  };

  const recentAnomalies = mlData?.recent_anomalies || [
    { type: 'Anti-Replay Violation', spi: '0x8f2a11b0', time: '10s ago', severity: 'High' },
    { type: 'IKE Negotiation Flood', spi: '0x00000000', time: '42s ago', severity: 'Critical' },
    { type: 'Low Entropy ESP Payload', spi: '0x3c99e120', time: '2m ago', severity: 'Medium' }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.3s ease' }}>
      {/* Top Banner / SIH Project Header */}
      <div style={{
        padding: '1.25rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(6, 182, 212, 0.08))',
        border: '1px solid rgba(6, 182, 212, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            padding: '2px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(6, 182, 212, 0.2)',
            color: 'var(--accent-cyan)',
            marginBottom: '6px'
          }}>
            <Radio size={12} /> REAL-TIME IPSEC / VPN TELEMETRY ACTIVE
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: '800', color: 'var(--text-bright)' }}>
            Enterprise VPN Security Posture & Protocol Health
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Continuous packet inspection, dual-engine ML anomaly detection, and automated NIST SP 800-77 compliance verification.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={() => onNavigate('security')}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <ShieldCheck size={16} />
            <span>Run Security Audit</span>
          </button>
          <button
            onClick={() => onNavigate('simulator')}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Flame size={16} />
            <span>Simulate Attacks</span>
          </button>
        </div>
      </div>

      {/* Quick Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '1.25rem'
      }}>
        {/* Metric 1 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: '600' }}>
              PACKETS INSPECTED
            </span>
            <div style={{ color: 'var(--accent-blue)', padding: '6px', backgroundColor: 'rgba(59, 130, 246, 0.1)', borderRadius: '6px' }}>
              <Layers size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-bright)', marginTop: '0.5rem' }}>
            {totalPackets.toLocaleString()}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
            ESP / AH / IKEv1 / IKEv2
          </div>
        </div>

        {/* Metric 2 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: '600' }}>
              ML ANOMALIES DETECTED
            </span>
            <div style={{ color: anomaliesCount > 0 ? 'var(--accent-orange)' : 'var(--accent-green)', padding: '6px', backgroundColor: anomaliesCount > 0 ? 'rgba(245, 158, 11, 0.1)' : 'rgba(16, 185, 129, 0.1)', borderRadius: '6px' }}>
              <Cpu size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: anomaliesCount > 0 ? 'var(--accent-orange)' : 'var(--accent-green)', marginTop: '0.5rem' }}>
            {anomaliesCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Isolation Forest + RF Classifier
          </div>
        </div>

        {/* Metric 3 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: '600' }}>
              CONFIG VULNERABILITIES
            </span>
            <div style={{ color: vulnsCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)', padding: '6px', backgroundColor: vulnsCount > 0 ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)', borderRadius: '6px' }}>
              <AlertTriangle size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: vulnsCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: '0.5rem' }}>
            {vulnsCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            NIST SP 800-77 violations
          </div>
        </div>

        {/* Metric 4 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: '600' }}>
              ACTIVE IPSEC SAs
            </span>
            <div style={{ color: 'var(--accent-purple)', padding: '6px', backgroundColor: 'rgba(139, 92, 246, 0.1)', borderRadius: '6px' }}>
              <Lock size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-bright)', marginTop: '0.5rem' }}>
            {activeSAs}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-green)', marginTop: '0.25rem' }}>
            Tunnels active & synchronized
          </div>
        </div>
      </div>

      {/* Main Row: Security Score + Protocol Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>
        {/* Security Gauge Card */}
        <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-bright)' }}>
              VPN Health & Resilience
            </h3>
            <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
              NIST BENCHMARK
            </span>
          </div>

          <div style={{ margin: '1.5rem 0' }}>
            <SecurityGauge score={score} size={210} label="Cryptographic & Protocol Integrity" />
          </div>

          <div style={{
            width: '100%',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'var(--bg-tertiary)',
            border: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Anti-Replay Window: <strong style={{ color: 'var(--accent-green)' }}>64 Packets</strong>
            </div>
            <button
              onClick={() => onNavigate('security')}
              className="btn btn-sm"
              style={{ padding: '3px 8px', fontSize: '0.75rem', color: 'var(--accent-cyan)', background: 'transparent' }}
            >
              Details <ArrowRight size={12} style={{ display: 'inline' }} />
            </button>
          </div>
        </div>

        {/* Protocol Breakdown & Traffic Mix */}
        <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                Protocol Traffic Composition
              </h3>
              <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                DISTRIBUTION
              </span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Real-time classification of Encapsulating Security Payload (ESP), Authentication Header (AH), and IKE tunnels.
            </p>

            <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {Object.entries(protocolDist).map(([proto, pct]) => {
                const colors = {
                  ESP: 'var(--accent-blue)',
                  IKEv2: 'var(--accent-cyan)',
                  IKEv1: 'var(--accent-orange)',
                  AH: 'var(--accent-purple)'
                };
                const color = colors[proto] || 'var(--accent-green)';
                const numericPct = typeof pct === 'number' ? pct : parseInt(pct) || 0;

                return (
                  <div key={proto}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '4px' }}>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{proto}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: color }}>{numericPct}%</span>
                    </div>
                    <div style={{
                      height: '8px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(255, 255, 255, 0.06)',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.min(100, numericPct)}%`,
                        backgroundColor: color,
                        borderRadius: '4px',
                        transition: 'width 0.8s ease'
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{
            marginTop: '1.5rem',
            padding: '0.75rem',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)'
          }}>
            <strong style={{ color: 'var(--accent-cyan)' }}>SIH Innovation Note:</strong> Protocol analyzer decapsulates ESP headers with zero plaintext leakage to maintain zero-trust compliance.
          </div>
        </div>
      </div>

      {/* Live Event Stream / Recent Anomalies */}
      <div className="card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-bright)' }}>
              Detected Anomaly Stream & Audit Trail
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Triggered by unsupervised Isolation Forest & signature checks
            </span>
          </div>
          <button
            onClick={() => onNavigate('anomalies')}
            className="btn btn-secondary btn-sm"
            style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
          >
            <span>View ML Engine</span>
            <ArrowRight size={13} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          {recentAnomalies.map((anomaly, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.75rem 1rem',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                flexWrap: 'wrap',
                gap: '0.5rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: anomaly.severity.toLowerCase() === 'critical' ? 'var(--accent-red)' : 'var(--accent-orange)'
                }} />
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: '600', color: 'var(--text-bright)' }}>
                    {anomaly.type}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    SPI Target: <span style={{ color: 'var(--accent-cyan)' }}>{anomaly.spi}</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  {anomaly.time}
                </span>
                <StatusBadge status={anomaly.severity} text={anomaly.severity} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
