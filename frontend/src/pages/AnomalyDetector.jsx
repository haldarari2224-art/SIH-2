import React, { useState } from 'react';
import {
  Cpu,
  TrendingUp,
  AlertOctagon,
  CheckCircle2,
  Sliders,
  Radio,
  Zap,
  Activity,
  Layers
} from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import ThreatCard from '../components/ThreatCard';

const AnomalyDetector = ({ mlData = {}, loading }) => {
  const [sensitivity, setSensitivity] = useState(0.05);

  const modelInfo = mlData.model_info || {
    unsupervised_model: 'Isolation Forest (scikit-learn)',
    supervised_model: 'Random Forest Classifier (n=100)',
    contamination_rate: sensitivity,
    accuracy: '98.4%',
    f1_score: '0.976'
  };

  const featureImportance = mlData.feature_importance || [
    { feature: 'Sequence Jump / Inversion', weight: 88, desc: 'Detects out-of-window replay violations' },
    { feature: 'Payload Byte Entropy', weight: 79, desc: 'Identifies unencrypted plaintext leaks or padding flaws' },
    { feature: 'Inter-Arrival Time Jitter', weight: 64, desc: 'Detects automated packet injection & probing' },
    { feature: 'SPI Variance / Frequency', weight: 58, desc: 'Flags SPI spoofing and SA desynchronization' },
    { feature: 'Packet Size Variance', weight: 42, desc: 'Detects burst flooding and tunneling exfiltration' }
  ];

  const detectedAnomalies = mlData.anomalies || [
    {
      title: 'IPsec Anti-Replay Window Violation',
      severity: 'High',
      details: 'Multiple ESP frames observed with duplicate sequence numbers (seq #142) outside the 64-packet anti-replay window.',
      remediation: 'Enable strict Extended Sequence Numbers (ESN 64-bit) in IPsec policy and configure anti-replay window size >= 128 packets.',
      affected_component: 'SPI: 0x8f2a11b0'
    },
    {
      title: 'IKE SA Negotiation Flooding (DDoS Probing)',
      severity: 'Critical',
      details: 'Sudden spike of 450 IKE_SA_INIT requests per second originating from unauthenticated source 203.0.113.44.',
      remediation: 'Enable IKEv2 Cookie validation (RFC 7296 section 2.6) to enforce stateless anti-DoS verification before allocating state.',
      affected_component: 'UDP Port 500 / IKEv2'
    },
    {
      title: 'Suspicious ESP Low Byte Entropy',
      severity: 'Medium',
      details: 'ESP payload byte entropy dropped to 4.2 bits/byte (expected > 7.8 for encrypted AES-GCM ciphertexts). Potential plaintext tunnel leak.',
      remediation: 'Audit cryptographic transform set on VPN gateway to ensure null-encryption (ESP-NULL) is completely disallowed.',
      affected_component: 'SPI: 0x3c99e120'
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.3s ease' }}>
      {/* ML Pipeline Banner */}
      <div style={{
        padding: '1.25rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.15), rgba(6, 182, 212, 0.08))',
        border: '1px solid rgba(139, 92, 246, 0.3)',
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
            backgroundColor: 'rgba(139, 92, 246, 0.2)',
            color: 'var(--accent-purple)',
            marginBottom: '6px'
          }}>
            <Cpu size={12} /> HYBRID UNSUPERVISED + SUPERVISED ML PIPELINE
          </div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: '800', color: 'var(--text-bright)' }}>
            AI-Driven VPN Anomaly Detection Engine
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Detects zero-day tunnel tampering, replay attacks, and exfiltration patterns without requiring plaintext decryption.
          </p>
        </div>

        <div style={{
          display: 'flex',
          gap: '1.25rem',
          backgroundColor: 'rgba(0, 0, 0, 0.25)',
          padding: '0.75rem 1.25rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>MODEL ACCURACY</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '800', color: 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>
              {modelInfo.accuracy}
            </div>
          </div>
          <div style={{ borderLeft: '1px solid rgba(255, 255, 255, 0.1)', paddingLeft: '1.25rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>F1-SCORE</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '800', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
              {modelInfo.f1_score}
            </div>
          </div>
        </div>
      </div>

      {/* Model Parameters & Feature Weights Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>
        {/* Left: Feature Importance */}
        <div className="card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-bright)' }}>
              ML Feature Importance (Random Forest)
            </h3>
            <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)' }}>
              WEIGHTS
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
            {featureImportance.map((item, idx) => (
              <div key={idx}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{item.feature}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)', fontWeight: '700' }}>
                    {item.weight}%
                  </span>
                </div>
                <div style={{
                  height: '7px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(255, 255, 255, 0.06)',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    height: '100%',
                    width: `${item.weight}%`,
                    background: 'linear-gradient(90deg, #8b5cf6, #06b6d4)',
                    borderRadius: '4px'
                  }} />
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '3px' }}>
                  {item.desc}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Isolation Forest Scatter / Score Distribution */}
        <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                Isolation Forest Anomaly Score Curve
              </h3>
              <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                OUTLIER SCORES
              </span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Samples with score &lt; -0.20 indicate severe multidimensional outliers away from the baseline IPsec manifold.
            </p>

            {/* Simulated Visual Graph / Bars */}
            <div style={{
              margin: '1.5rem 0',
              padding: '1.25rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: '#030712',
              border: '1px solid var(--border-color)',
              display: 'flex',
              alignItems: 'flex-end',
              justifyContent: 'space-between',
              height: '140px',
              gap: '6px'
            }}>
              {[0.12, 0.08, 0.15, 0.22, 0.18, 0.10, -0.45, -0.62, 0.14, 0.09, 0.11, -0.51, 0.19, 0.12, 0.08, 0.20].map((val, i) => {
                const isAnomaly = val < 0;
                const heightPct = Math.abs(val) * 100;
                return (
                  <div
                    key={i}
                    style={{
                      flex: 1,
                      height: `${Math.max(15, Math.min(100, heightPct))}%`,
                      backgroundColor: isAnomaly ? 'var(--accent-red)' : 'rgba(6, 182, 212, 0.4)',
                      borderRadius: '3px',
                      transition: 'height 0.3s ease',
                      position: 'relative'
                    }}
                    title={`Sample ${i + 1}: Score ${val}`}
                  />
                );
              })}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <span>Baseline Safe Cluster (+0.1 to +0.3)</span>
              <span style={{ color: 'var(--accent-red)' }}>Anomaly Cluster (-0.4 to -0.7)</span>
            </div>
          </div>

          <div style={{
            marginTop: '1.25rem',
            padding: '0.85rem',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'var(--bg-tertiary)',
            border: '1px solid var(--border-color)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-primary)', fontWeight: '600' }}>
                Anomaly Sensitivity Threshold:
              </span>
              <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                {(sensitivity * 100).toFixed(0)}% Contamination
              </span>
            </div>
            <input
              type="range"
              min="0.01"
              max="0.20"
              step="0.01"
              value={sensitivity}
              onChange={(e) => setSensitivity(parseFloat(e.target.value))}
              style={{ width: '100%', marginTop: '6px', cursor: 'pointer' }}
            />
          </div>
        </div>
      </div>

      {/* Detected Anomalies List */}
      <div>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '800', color: 'var(--text-bright)', marginBottom: '0.85rem' }}>
          Active Anomalies & Threat Intel ({detectedAnomalies.length})
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {detectedAnomalies.map((item, idx) => (
            <ThreatCard key={idx} item={item} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default AnomalyDetector;
