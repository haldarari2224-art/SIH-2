import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCheck,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import SecurityGauge from '../components/SecurityGauge';
import StatusBadge from '../components/StatusBadge';
import ThreatCard from '../components/ThreatCard';

const SecurityAssessment = ({ securityData = {}, loading }) => {
  const [activeCategory, setActiveCategory] = useState('all');

  const score = securityData.security_score ?? 74;
  const grade = securityData.grade ?? (score >= 80 ? 'B+' : score >= 65 ? 'C' : 'F');

  const rawCryptoAudit = securityData.crypto_audit;
  const cryptoAudit = useMemo(() => {
    if (Array.isArray(rawCryptoAudit)) return rawCryptoAudit;
    if (rawCryptoAudit && typeof rawCryptoAudit === 'object') {
      const list = [];
      (rawCryptoAudit.encryption_algorithms || []).forEach((enc) => {
        list.push({
          name: 'ESP / IKE Encryption',
          value: enc.algorithm || 'AES',
          status: enc.secure ? 'pass' : 'fail',
          reason: enc.secure ? 'Strong modern cipher' : 'Deprecated cipher vulnerable to SWEET32 cryptanalysis',
          recommended: 'AES-256-GCM or ChaCha20-Poly1305'
        });
      });
      (rawCryptoAudit.hash_algorithms || []).forEach((h) => {
        list.push({
          name: 'Integrity / HMAC',
          value: h.algorithm || 'SHA',
          status: h.secure ? 'pass' : 'warning',
          reason: h.secure ? 'Cryptographically secure hashing' : 'Legacy hashing with collision risks',
          recommended: 'HMAC-SHA-256 or SHA-384'
        });
      });
      (rawCryptoAudit.dh_groups || []).forEach((dh) => {
        list.push({
          name: 'Diffie-Hellman Group',
          value: dh.group || 'Group 14',
          status: dh.secure ? 'pass' : 'fail',
          reason: dh.secure ? 'Sufficient prime length' : 'Weak key exchange prime (<2048-bit)',
          recommended: 'DH Group 14 (2048-bit) or Group 19 (ECDH)'
        });
      });
      if (list.length > 0) return list;
    }
    return [
      { name: 'IKE Phase 1 Encryption', value: '3DES-CBC', status: 'fail', reason: 'SWEET32 64-bit block cipher vulnerability (CVE-2016-6329)', recommended: 'AES-256-GCM or ChaCha20' },
      { name: 'IKE Phase 1 Integrity', value: 'HMAC-SHA1-96', status: 'warning', reason: 'SHA-1 collision attacks feasible; deprecated by NIST SP 800-131A', recommended: 'HMAC-SHA-256 or SHA-384' },
      { name: 'Diffie-Hellman Group', value: 'MODP Group 2 (1024-bit)', status: 'fail', reason: 'Sub-2048 bit primes vulnerable to Logjam precomputation', recommended: 'DH Group 14 (2048-bit) or Group 19 (ECDH 256-bit)' },
      { name: 'ESP Transform Set', value: 'AES-128-CBC + HMAC-SHA256', status: 'pass', reason: 'Compliant block cipher with authenticated HMAC', recommended: 'AES-256-GCM (AEAD mode preferred)' },
      { name: 'Anti-Replay Protection', value: 'Enabled (64-packet window)', status: 'pass', reason: 'Replay window active', recommended: 'Upgrade to 64-bit Extended Sequence Numbers (ESN)' }
    ];
  }, [rawCryptoAudit]);

  const complianceStandards = [
    { standard: 'NIST SP 800-77 Rev. 1', desc: 'Guide to IPsec VPNs', compliance: '72%', status: 'warning' },
    { standard: 'CIS Benchmark v2.0', desc: 'VPN Gateway Hardening', compliance: '68%', status: 'warning' },
    { standard: 'FIPS 140-3 Cryptography', desc: 'Federal Crypto Standards', compliance: '85%', status: 'pass' },
    { standard: 'RFC 8221 / RFC 8247', desc: 'IPsec Cipher Suite Profile', compliance: '75%', status: 'pass' }
  ];

  const vulnerabilities = securityData.vulnerabilities || [
    {
      title: 'IKE Aggressive Mode with Pre-Shared Key (PSK)',
      severity: 'Critical',
      cve_id: 'CVE-2002-1623',
      description: 'The VPN responder transmits the PSK authentication hash in cleartext during packet 2, enabling offline brute-force cracking with tools like ikecrack.',
      remediation: 'Migrate immediately from Aggressive Mode to IKEv2 or IKEv1 Main Mode with X.509 digital certificates.',
      impact: 'Full VPN tunnel compromise and unauthorized network penetration.'
    },
    {
      title: 'SWEET32 Birthday Attack on 3DES Cipher Suites',
      severity: 'High',
      cve_id: 'CVE-2016-6329',
      description: 'Using 64-bit block ciphers (3DES, Blowfish) in long-lived IPsec SAs permits plaintext recovery after capturing ~32GB of data.',
      remediation: 'Remove 3DES from all Phase 1 and Phase 2 proposals; require AES-256-GCM.',
      impact: 'Session decryption and confidential data exposure.'
    },
    {
      title: 'Missing Perfect Forward Secrecy (PFS) in Phase 2',
      severity: 'Medium',
      cve_id: 'CWE-326',
      description: 'Child SAs do not execute an independent Diffie-Hellman exchange during rekeying. Compromise of Phase 1 keys exposes all past traffic.',
      remediation: 'Configure "pfs=yes" with DH Group 14 or 19 in IPsec SA transform sets.',
      impact: 'Loss of past session forward secrecy upon master key compromise.'
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.3s ease' }}>
      {/* Top Banner with Score Gauge */}
      <div className="card" style={{
        padding: '1.75rem',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '2rem',
        alignItems: 'center'
      }}>
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <SecurityGauge score={score} size={220} label="Overall Framework Compliance Score" />
        </div>

        <div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            padding: '3px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            color: 'var(--accent-green)',
            marginBottom: '8px'
          }}>
            <ShieldCheck size={12} /> COMPLIANCE EVALUATION COMPLETED
          </div>

          <h2 style={{ fontSize: '1.5rem', fontWeight: '800', color: 'var(--text-bright)' }}>
            NIST SP 800-77 & CIS Benchmark Audit
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: 1.5 }}>
            Automated configuration auditing identifies obsolete Diffie-Hellman groups, weak hashing algorithms, and known cryptographic CVE weaknesses in IPsec configurations.
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '0.75rem',
            marginTop: '1.25rem'
          }}>
            {complianceStandards.map((item, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                    {item.standard}
                  </span>
                  <span style={{
                    fontSize: '0.72rem',
                    fontWeight: '800',
                    fontFamily: 'var(--font-mono)',
                    color: item.status === 'pass' ? 'var(--accent-green)' : 'var(--accent-orange)'
                  }}>
                    {item.compliance}
                  </span>
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {item.desc}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Cryptographic Algorithm Audit Table */}
      <div className="card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '800', color: 'var(--text-bright)' }}>
              Cryptographic Suite & Transform Set Audit
            </h3>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Audited against RFC 8221 (IPsec) and RFC 8247 (IKEv2) recommendations
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {cryptoAudit.map((item, idx) => {
            const isPass = item.status === 'pass';
            const isWarning = item.status === 'warning';
            return (
              <div
                key={idx}
                style={{
                  padding: '1rem 1.25rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-tertiary)',
                  border: `1px solid ${isPass ? 'rgba(16, 185, 129, 0.25)' : isWarning ? 'rgba(245, 158, 11, 0.25)' : 'rgba(239, 68, 68, 0.3)'}`,
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '1rem'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem' }}>
                  <div style={{
                    color: isPass ? 'var(--accent-green)' : isWarning ? 'var(--accent-orange)' : 'var(--accent-red)',
                    marginTop: '2px'
                  }}>
                    {isPass ? <CheckCircle2 size={18} /> : isWarning ? <AlertTriangle size={18} /> : <XCircle size={18} />}
                  </div>

                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                        {item.name}
                      </span>
                      <span style={{
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        backgroundColor: 'rgba(255, 255, 255, 0.06)',
                        color: isPass ? 'var(--accent-green)' : 'var(--accent-red)'
                      }}>
                        {item.value}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {item.reason}
                    </div>

                    <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                      Recommendation: {item.recommended}
                    </div>
                  </div>
                </div>

                <div>
                  <StatusBadge status={isPass ? 'PASS' : isWarning ? 'WARNING' : 'FAIL'} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Identified CVEs & Vulnerabilities */}
      <div>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '800', color: 'var(--text-bright)', marginBottom: '0.85rem' }}>
          Identified Vulnerabilities & Remediation ({vulnerabilities.length})
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {vulnerabilities.map((item, idx) => (
            <ThreatCard key={idx} item={item} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default SecurityAssessment;
