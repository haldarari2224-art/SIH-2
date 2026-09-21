import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import ProtocolAnalyzer from './pages/ProtocolAnalyzer';
import AnomalyDetector from './pages/AnomalyDetector';
import SecurityAssessment from './pages/SecurityAssessment';
import AttackSimulator from './pages/AttackSimulator';
import Reports from './pages/Reports';
import api from './services/api';

// Realistic fallback initial state for zero-latency presentation
const FALLBACK_STATE = {
  sessionId: 'sih-demo-session-001',
  scenario: 'corporate_vpn',
  stats: {
    total_packets: 520,
    security_score: 76,
    anomalies_detected: 4,
    vulnerabilities_count: 3,
    active_sas_count: 4
  },
  analysis: {
    summary: {
      total_packets: 520,
      active_sas: 4,
      protocol_distribution: { ESP: 74, IKEv2: 16, IKEv1: 6, AH: 4 }
    }
  },
  packets: Array.from({ length: 45 }, (_, i) => ({
    id: `pkt-${i + 1}`,
    timestamp: new Date(Date.now() - (45 - i) * 2000).toISOString(),
    src_ip: i % 2 === 0 ? '192.168.1.105' : '10.200.50.12',
    dst_ip: i % 2 === 0 ? '10.200.50.12' : '192.168.1.105',
    protocol: i === 0 || i === 1 ? 'IKEv2' : i === 12 ? 'AH' : 'ESP',
    spi: i % 3 === 0 ? '0x8f2a11b0' : i % 3 === 1 ? '0x4c99e120' : '0x7b11d9a2',
    seq_num: 100 + i * (i === 15 ? 0 : 1), // Plant duplicate for replay
    size_bytes: i % 4 === 0 ? 1420 : i % 4 === 1 ? 512 : 1280,
    is_anomaly: i === 15 || i === 28 || i === 39,
    anomaly_type: i === 15 ? 'Sequence Replay Violation' : i === 28 ? 'Entropy Drop (Plaintext leak)' : 'Unsolicited SPI probe',
    anomaly_reason: i === 15 ? 'Identical Sequence Number received outside anti-replay window.' : 'Entropy anomaly detected.'
  })),
  ml: {
    model_info: {
      unsupervised_model: 'Isolation Forest (scikit-learn)',
      supervised_model: 'Random Forest Classifier (n=100)',
      contamination_rate: 0.05,
      accuracy: '98.4%',
      f1_score: '0.976'
    },
    anomalies_count: 3,
    recent_anomalies: [
      { type: 'Anti-Replay Window Violation', spi: '0x8f2a11b0', time: '12s ago', severity: 'High' },
      { type: 'IKE SA Flood (Half-Open Probing)', spi: '0x00000000', time: '55s ago', severity: 'Critical' },
      { type: 'Low Byte Entropy ESP Payload', spi: '0x3c99e120', time: '3m ago', severity: 'Medium' }
    ]
  },
  security: {
    security_score: 74,
    grade: 'B',
    vulnerabilities: [
      {
        title: 'IKE Aggressive Mode with Pre-Shared Key (PSK)',
        severity: 'Critical',
        cve_id: 'CVE-2002-1623',
        description: 'Responder transmits PSK authentication hash unencrypted during packet 2, permitting offline dictionary attacks.',
        remediation: 'Migrate Phase 1 to IKEv2 or IKEv1 Main Mode with digital certificate authentication.'
      },
      {
        title: 'SWEET32 Birthday Collisions (3DES-CBC)',
        severity: 'High',
        cve_id: 'CVE-2016-6329',
        description: '64-bit block size susceptible to plaintext recovery collisions after prolonged tunnel usage.',
        remediation: 'Require AES-256-GCM or ChaCha20-Poly1305 in Phase 2 transform sets.'
      },
      {
        title: 'Diffie-Hellman Group 2 (1024-bit MODP) Deprecation',
        severity: 'Medium',
        cve_id: 'CWE-326',
        description: '1024-bit primes vulnerable to state-sponsored precomputation (Logjam attack).',
        remediation: 'Upgrade to DH Group 14 (2048-bit) or Group 19 (ECDH 256-bit).'
      }
    ]
  }
};

function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [activeScenario, setActiveScenario] = useState('corporate_vpn');
  const [activeSession, setActiveSession] = useState(FALLBACK_STATE.sessionId);
  const [backendConnected, setBackendConnected] = useState(false);
  const [loading, setLoading] = useState(false);

  // Core Data States
  const [stats, setStats] = useState(FALLBACK_STATE.stats);
  const [analysisData, setAnalysisData] = useState(FALLBACK_STATE.analysis);
  const [packets, setPackets] = useState(FALLBACK_STATE.packets);
  const [mlData, setMlData] = useState(FALLBACK_STATE.ml);
  const [securityData, setSecurityData] = useState(FALLBACK_STATE.security);
  const [simulationData, setSimulationData] = useState(null);
  const [reportData, setReportData] = useState(null);

  // Initialize and check backend connection
  const loadScenarioData = useCallback(async (scenarioName) => {
    setLoading(true);
    try {
      const res = await api.loadDemo(scenarioName, 500);
      if (res && res.session_id) {
        setActiveSession(res.session_id);
        setBackendConnected(true);

        // Fetch session details from backend
        try {
          const [analysisRes, mlRes, scanRes, statsRes] = await Promise.all([
            api.getAnalysis(res.session_id).catch(() => null),
            api.getMLResults(res.session_id).catch(() => null),
            api.getScanResults(res.session_id).catch(() => null),
            api.getDashboardStats(res.session_id).catch(() => null)
          ]);

          if (analysisRes) {
            setAnalysisData(analysisRes);
            if (analysisRes.packets) setPackets(analysisRes.packets);
          }
          if (mlRes) setMlData(mlRes);
          if (scanRes) setSecurityData(scanRes);
          if (statsRes) setStats(statsRes);
        } catch (err) {
          console.warn('Could not fetch all backend modules; using populated demo state:', err);
        }
      }
    } catch (err) {
      console.warn('Backend currently offline or unreachable; operating in autonomous demo mode.', err);
      setBackendConnected(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial health check & load
    api.health()
      .then(() => {
        setBackendConnected(true);
        loadScenarioData(activeScenario);
      })
      .catch(() => {
        setBackendConnected(false);
      });
  }, [loadScenarioData, activeScenario]);

  // Handle Scenario Change
  const handleScenarioChange = (newScenario) => {
    setActiveScenario(newScenario);
    loadScenarioData(newScenario);
  };

  // Handle File Upload
  const handleFileUpload = async (file) => {
    setLoading(true);
    try {
      const res = await api.uploadPcap(file);
      if (res && res.session_id) {
        setActiveSession(res.session_id);
        const [analysisRes, mlRes, scanRes, statsRes] = await Promise.all([
          api.getAnalysis(res.session_id).catch(() => null),
          api.getMLResults(res.session_id).catch(() => null),
          api.getScanResults(res.session_id).catch(() => null),
          api.getDashboardStats(res.session_id).catch(() => null)
        ]);
        if (analysisRes) {
          setAnalysisData(analysisRes);
          if (analysisRes.packets) setPackets(analysisRes.packets);
        }
        if (mlRes) setMlData(mlRes);
        if (scanRes) setSecurityData(scanRes);
        if (statsRes) setStats(statsRes);
      }
    } catch (err) {
      alert(`PCAP Upload Error: ${err.message}. (Ensure backend server is running)`);
    } finally {
      setLoading(false);
    }
  };

  // Handle Attack Simulation
  const handleRunSimulation = async (attackType) => {
    try {
      if (backendConnected && activeSession) {
        const res = await api.request(`/simulate/${activeSession}?attack_type=${attackType}`, {
          method: 'POST'
        });
        setSimulationData(res);
        return res;
      }
    } catch (err) {
      console.warn('Simulation API error; falling back to local simulator:', err);
    }
    return null;
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-primary)' }}>
      {/* Top App Header */}
      <Header
        activeSession={activeSession}
        activeScenario={activeScenario}
        onScenarioChange={handleScenarioChange}
        onReloadDemo={() => loadScenarioData(activeScenario)}
        backendConnected={backendConnected}
        loading={loading}
      />

      {/* Main Workspace Layout */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Left Sidebar Navigation */}
        <Sidebar
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          stats={stats}
        />

        {/* Viewport Content Area */}
        <main style={{
          flex: 1,
          padding: '1.75rem 2rem',
          maxWidth: '1600px',
          margin: '0 auto',
          width: '100%',
          boxSizing: 'border-box'
        }}>
          {currentTab === 'dashboard' && (
            <Dashboard
              stats={stats}
              analysisData={analysisData}
              securityData={securityData}
              mlData={mlData}
              loading={loading}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'analyzer' && (
            <ProtocolAnalyzer
              packets={packets}
              summary={analysisData?.summary}
              loading={loading}
              onFileUpload={handleFileUpload}
              onSampleLoad={() => loadScenarioData(activeScenario)}
            />
          )}

          {currentTab === 'anomalies' && (
            <AnomalyDetector
              mlData={mlData}
              loading={loading}
            />
          )}

          {currentTab === 'security' && (
            <SecurityAssessment
              securityData={securityData}
              loading={loading}
            />
          )}

          {currentTab === 'simulator' && (
            <AttackSimulator
              onRunSimulation={handleRunSimulation}
              simulationData={simulationData}
              loading={loading}
            />
          )}

          {currentTab === 'reports' && (
            <Reports
              reportData={reportData || {
                security_score: securityData?.security_score ?? 74,
                grade: securityData?.grade ?? 'B',
                generated_at: new Date().toLocaleString(),
                executive_summary: [
                  'Automated IPsec cryptographic posture and anomaly analysis was executed.',
                  `Achieved security score: ${securityData?.security_score ?? 74}/100.`,
                  'Immediate action required: Remove 3DES-CBC and replace IKE Aggressive mode with IKEv2 certificate exchange.'
                ]
              }}
              stats={stats}
              securityData={securityData}
              mlData={mlData}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
