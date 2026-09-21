import React, { useState } from 'react';
import { ChevronDown, ChevronUp, AlertTriangle, Shield, CheckCircle2, Copy } from 'lucide-react';
import StatusBadge from './StatusBadge';

const ThreatCard = ({ item }) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const title = item.title || item.name || item.type || 'Detected Security Anomaly';
  const severity = item.severity || 'Medium';
  const cve = item.cve_id || item.cve || null;
  const description = item.description || item.details || item.msg || '';
  const remediation = item.remediation || item.fix || item.recommendation || '';
  const affected = item.affected_component || item.spi || item.protocol || null;

  const handleCopyRemediation = (e) => {
    e.stopPropagation();
    if (remediation) {
      navigator.clipboard.writeText(remediation);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        padding: '1rem 1.25rem',
        cursor: 'pointer',
        transition: 'all var(--transition-fast)',
        position: 'relative',
        overflow: 'hidden'
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'var(--border-hover)';
        e.currentTarget.style.backgroundColor = 'var(--bg-card-hover)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--border-color)';
        e.currentTarget.style.backgroundColor = 'var(--bg-card)';
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', flex: 1 }}>
          <div style={{
            padding: '6px',
            borderRadius: '6px',
            backgroundColor: severity.toLowerCase() === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
            color: severity.toLowerCase() === 'critical' ? 'var(--accent-red)' : 'var(--accent-orange)',
            marginTop: '2px'
          }}>
            <AlertTriangle size={18} />
          </div>

          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                {title}
              </span>
              <StatusBadge status={severity} text={severity} />
              {cve && (
                <span style={{
                  fontSize: '0.7rem',
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(139, 92, 246, 0.15)',
                  border: '1px solid rgba(139, 92, 246, 0.3)',
                  color: 'var(--accent-purple)'
                }}>
                  {cve}
                </span>
              )}
            </div>

            <p style={{
              fontSize: '0.82rem',
              color: 'var(--text-secondary)',
              marginTop: '0.35rem',
              lineHeight: 1.4
            }}>
              {description}
            </p>

            {affected && (
              <div style={{
                fontSize: '0.72rem',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                marginTop: '0.4rem'
              }}>
                Target: <span style={{ color: 'var(--accent-cyan)' }}>{affected}</span>
              </div>
            )}
          </div>
        </div>

        <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </div>
      </div>

      {expanded && (
        <div style={{
          marginTop: '1rem',
          paddingTop: '0.85rem',
          borderTop: '1px solid var(--border-color)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.6rem',
          animation: 'fadeIn 0.2s ease'
        }}>
          {remediation && (
            <div style={{
              backgroundColor: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '6px',
              padding: '0.75rem',
              position: 'relative'
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '4px'
              }}>
                <span style={{
                  fontSize: '0.72rem',
                  fontWeight: '700',
                  color: 'var(--accent-green)',
                  letterSpacing: '0.05em',
                  textTransform: 'uppercase',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  <Shield size={12} /> Prescribed Remediation
                </span>

                <button
                  onClick={handleCopyRemediation}
                  className="btn btn-sm"
                  style={{
                    padding: '2px 8px',
                    fontSize: '0.7rem',
                    background: 'transparent',
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    color: 'var(--accent-green)'
                  }}
                >
                  <Copy size={11} /> {copied ? 'Copied!' : 'Copy Fix'}
                </button>
              </div>

              <div style={{
                fontSize: '0.8rem',
                color: 'var(--text-primary)',
                lineHeight: 1.5,
                fontFamily: 'var(--font-mono)'
              }}>
                {remediation}
              </div>
            </div>
          )}

          {item.impact && (
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              <strong style={{ color: 'var(--text-secondary)' }}>Impact Analysis:</strong> {item.impact}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatCard;
