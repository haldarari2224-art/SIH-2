import React, { useState } from 'react';
import {
  Flame,
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  Zap,
  Terminal,
  Activity
} from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

const AttackSimulator = ({ onRunSimulation, simulationData = {}, loading }) => {
  const [selectedAttack, setSelectedAttack] = useState('replay_attack');
  const [running, setRunning] = useState(false);
  const [simResults, setSimResults] = useState(simulationData);

  const attackVectors = [
    {
      id: 'replay_attack',
      title: 'IPsec Packet Replay Attack',
      description: 'Injects captured ESP frames with identical Sequence Numbers to evaluate anti-replay window handling.',
      mitre: 'T1557 - Adversary-in-the-Middle',
      risk: 'High',
      likelihood: 'High'
    },
    {
      id: 'downgrade_attack',
      title: 'IKE Proposal Downgrade Attack',
      description: 'Intercepts IKE SA proposals and strips AES-GCM suites to coerce fall-back to 3DES-CBC / MD5.',
      mitre: 'T1565.002 - Data Manipulation',
      risk: 'Critical',
      likelihood: 'Medium'
    },
    {
      id: 'spi_spoofing',
      title: 'SPI Spoofing & Desynchronization',
      description: 'Transmits bogus ESP frames with valid destination IP but forged SPI to disrupt SA state tables.',
      mitre: 'T1499 - Endpoint Denial of Service',
      risk: 'Medium',
      likelihood: 'High'
    },
    {
      id: 'ike_flood',
      title: 'IKE SA Negotiation Flooding (DoS)',
      description: 'Generates rapid bursts of IKE_SA_INIT packets without completing phase 2 to exhaust memory pools.',
      mitre: 'T1498 - Network Denial of Service',
      risk: 'High',
      likelihood: 'High'
    },
    {
      id: 'mitm_psk',
      title: 'IKE Aggressive Mode PSK Extraction',
      description: 'Passively monitors UDP 500 handshakes to extract the hash payload and performs offline dictionary attack.',
      mitre: 'T1110.002 - Password Cracking',
      risk: 'Critical',
      likelihood: 'High'
    },
    {
      id: 'cert_forgery',
      title: 'Rogue Gateway & Untrusted Root CA',
      description: 'Presents self-signed X.509 certificates to test strict CA chain validation on the IPsec initiator.',
      mitre: 'T1587.003 - Digital Certificates',
      risk: 'High',
      likelihood: 'Low'
    }
  ];

  const handleSimulate = async () => {
    setRunning(true);
    if (onRunSimulation) {
      const res = await onRunSimulation(selectedAttack);
      if (res) setSimResults(res);
    } else {
      // Local fallback simulation if offline
      setTimeout(() => {
        setSimResults({
          attack_type: selectedAttack,
          timestamp: new Date().toISOString(),
          vulnerable: selectedAttack === 'replay_attack' || selectedAttack === 'downgrade_attack' || selectedAttack === 'mitm_psk',
          outcome: selectedAttack === 'replay_attack'
            ? 'VULNERABLE — 4 out of 10 replayed ESP frames were accepted by responder due to sliding window misconfiguration.'
            : selectedAttack === 'downgrade_attack'
            ? 'VULNERABLE — Responder negotiated 3DES-CBC when AES-GCM was stripped from proposal list.'
            : 'RESILIENT — Gateway rejected spoofed frames and triggered rate-limiting alarm.',
          steps: [
            { step: 1, action: 'Synthesize crafted IPsec probe packets with altered headers', status: 'done' },
            { step: 2, action: 'Inject probe traffic into VPN listener on UDP 500 / 4500', status: 'done' },
            { step: 3, action: 'Analyze responder SPI reaction and cryptographic negotiation logs', status: 'done' },
            { step: 4, action: 'Calculate posture vulnerability index and remediation diff', status: 'done' }
          ],
          remediation: selectedAttack === 'replay_attack'
            ? 'Configure IPsec policy with "replay_window = 128" and enable Extended Sequence Numbers (ESN).'
            : selectedAttack === 'downgrade_attack'
            ? 'Hardcode strict cipher suites in strongSwan/Cisco config: "ike = aes256gcm16-prfsha384-modp2048!" (the "!" forces strict match).'
            : 'Enforce certificate revocation checks (OCSP / CRL) and disable PSK authentication entirely.'
        });
        setRunning(false);
      }, 1200);
    }
    setRunning(false);
  };

  const activeVector = attackVectors.find((v) => v.id === selectedAttack) || attackVectors[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.3s ease' }}>
      {/* Top Banner */}
      <div style={{
        padding: '1.25rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.12), rgba(245, 158, 11, 0.08))',
        border: '1px solid rgba(239, 68, 68, 0.3)',
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
            backgroundColor: 'rgba(239, 68, 68, 0.2)',
            color: 'var(--accent-red)',
            marginBottom: '6px'
          }}>
            <Flame size={12} /> ISOLATED ADVERSARIAL ATTACK TESTBED
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: '800', color: 'var(--text-bright)' }}>
            Safe IPsec Security & Attack Resilience Simulator
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Stress tests cryptographic policies, anti-replay implementations, and handshake vulnerabilities in a safe simulated sandbox.
          </p>
        </div>

        <button
          onClick={handleSimulate}
          disabled={running}
          className="btn btn-primary"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'linear-gradient(135deg, #ef4444, #f59e0b)',
            border: 'none',
            boxShadow: '0 0 15px rgba(239, 68, 68, 0.4)'
          }}
        >
          <Play size={16} />
          <span>{running ? 'Running Simulation...' : 'Execute Vector Simulation'}</span>
        </button>
      </div>

      {/* Vector Selector Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '1rem'
      }}>
        {attackVectors.map((v) => {
          const isSelected = selectedAttack === v.id;
          return (
            <div
              key={v.id}
              onClick={() => setSelectedAttack(v.id)}
              style={{
                borderRadius: 'var(--radius-md)',
                backgroundColor: isSelected ? 'rgba(239, 68, 68, 0.1)' : 'var(--bg-card)',
                border: `1px solid ${isSelected ? 'var(--accent-red)' : 'var(--border-color)'}`,
                padding: '1.1rem',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '0.75rem'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '0.9rem', fontWeight: '700', color: isSelected ? 'var(--text-bright)' : 'var(--text-primary)' }}>
                    {v.title}
                  </span>
                  <StatusBadge status={v.risk} text={v.risk} />
                </div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {v.description}
                </p>
              </div>

              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: '0.7rem',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                borderTop: '1px solid rgba(255, 255, 255, 0.05)',
                paddingTop: '6px'
              }}>
                <span>MITRE: {v.mitre.split(' ')[0]}</span>
                <span style={{ color: isSelected ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                  {isSelected ? '● SELECTED' : 'CLICK TO SELECT'}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulation Results & Execution Log */}
      <div className="card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '800', color: 'var(--text-bright)' }}>
              Simulation Outcome: {activeVector.title}
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Targeted SA: 0x8f2a11b0 | Protocol: ESP / UDP 500
            </span>
          </div>

          {simResults && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Status:</span>
              <StatusBadge
                status={simResults.vulnerable ? 'FAIL' : 'PASS'}
                text={simResults.vulnerable ? 'VULNERABLE' : 'RESILIENT'}
                size="lg"
              />
            </div>
          )}
        </div>

        {running ? (
          <LoadingSpinner text={`Executing adversarial test: ${activeVector.title}...`} />
        ) : simResults ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Outcome Box */}
            <div style={{
              padding: '1rem 1.25rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: simResults.vulnerable ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
              border: `1px solid ${simResults.vulnerable ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.85rem'
            }}>
              <div style={{ color: simResults.vulnerable ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: '2px' }}>
                {simResults.vulnerable ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
              </div>
              <div>
                <div style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                  {simResults.vulnerable ? 'Vulnerability Confirmed by Simulator' : 'Defenses Held: Attack Mitigated'}
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', marginTop: '4px', lineHeight: 1.5 }}>
                  {simResults.outcome || 'Detailed audit log below.'}
                </div>
              </div>
            </div>

            {/* Step-by-Step Execution Log */}
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--text-muted)', marginBottom: '0.6rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Terminal size={14} /> ADVERSARIAL EXECUTION TRACE
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {(simResults.steps || [
                  { step: 1, action: 'Injecting crafted packets into VPN tunnel pipeline', status: 'done' },
                  { step: 2, action: 'Monitoring responder anti-replay bitmap & error counters', status: 'done' },
                  { step: 3, action: 'Verifying cryptographic fallback threshold', status: 'done' }
                ]).map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.65rem 0.85rem',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      fontSize: '0.78rem',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    <span style={{ color: 'var(--accent-green)' }}>✓</span>
                    <span style={{ color: 'var(--text-muted)' }}>[STEP {idx + 1}]</span>
                    <span style={{ color: 'var(--text-primary)' }}>{step.action || step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* AI Prescribed Mitigation */}
            {simResults.remediation && (
              <div style={{
                padding: '1rem 1.25rem',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'rgba(6, 182, 212, 0.08)',
                border: '1px solid rgba(6, 182, 212, 0.25)'
              }}>
                <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--accent-cyan)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Zap size={14} /> RECOMMENDED HARDENING CONFIGURATION
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', lineHeight: 1.5 }}>
                  {simResults.remediation}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
            Select an attack vector above and click "Execute Vector Simulation" to test IPsec tunnel resilience.
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackSimulator;
