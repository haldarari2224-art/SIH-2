# 🛡️ IPsec Sentinel — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

> **Smart India Hackathon (SIH) Project**  
> An advanced, zero-trust network defense framework for real-time IPsec/VPN protocol analysis, ML-driven anomaly detection, cryptographic vulnerability auditing, and automated adversarial attack simulation.

---

## 🚀 Key Highlights & Innovations

1. **Protocol Inspection Engine (Scapy)**
   - Decapsulates and inspects ESP (Encapsulating Security Payload), AH (Authentication Header), and IKEv1/IKEv2 packets.
   - Extracts Security Parameter Index (SPI), sequence numbers, transform sets, and encapsulation modes (Tunnel vs Transport).
   - Zero Plaintext Leakage: Performs inspection on header structures and statistical entropy without requiring payload decryption.

2. **Dual-Model ML Anomaly Detector**
   - **Unsupervised Isolation Forest**: Identifies out-of-distribution traffic, sequence jumps, and low-entropy anomalies.
   - **Supervised Random Forest (n=100)**: Classifies attack signatures (anti-replay violations, IKE DoS floods, SPI spoofing, cipher downgrade attempts).
   - Live feature importance breakdown with configurable contamination sensitivity.

3. **Cryptographic & Compliance Audit (NIST SP 800-77 & CIS)**
   - Audits transform sets against RFC 8221 & RFC 8247 standards.
   - Automatically detects legacy ciphers (DES, 3DES/SWEET32, Blowfish), weak hashing (MD5, SHA-1), and insecure Diffie-Hellman groups (DH Group 1, 2, 5).
   - Identifies high-risk configurations like IKE Aggressive Mode with cleartext PSK hashes (CVE-2002-1623) and missing Perfect Forward Secrecy (PFS).

4. **Interactive Attack Resilience Simulator**
   - Stress-tests VPN tunnel configurations against 6 adversarial attack vectors:
     1. IPsec Packet Replay Attack (Anti-replay window exhaustion)
     2. IKE Proposal Downgrade Attack (Cipher suite manipulation)
     3. SPI Spoofing & Desynchronization
     4. IKE SA Negotiation Flooding (DDoS testbed)
     5. Aggressive Mode PSK Extraction & Offline Cracking
     6. Rogue VPN Gateway & Certificate Spoofing
   - Evaluates resilience, displays execution traces, and computes immediate hardening configs.

5. **AI Security Reports & Remediation Roadmap**
   - Automatically synthesizes executive reports with posture scores (0-100) and letter grades (A+ to F).
   - Provides prioritized remediation roadmaps (P0 Immediate, P1 High, P2 Scheduled).
   - Supports 1-click JSON export and formatted printable reports for stakeholders.

6. **Cyberpunk Dark Glassmorphism UI**
   - Custom-engineered design system with glowing accents, animated SVG circular score gauges, deep packet inspectors, and live telemetry feeds.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React + Vite Frontend                    │
│   ┌───────────────┬──────────────────┬──────────────────┐   │
│   │   Dashboard   │ Protocol Analyzer│ Anomaly Detector │   │
│   ├───────────────┼──────────────────┼──────────────────┤   │
│   │ Security Audit│ Attack Simulator │ AI Report Export │   │
│   └───────────────┴──────────────────┴──────────────────┘   │
└──────────────────────────────▲──────────────────────────────┘
                               │ REST API / WebSocket
┌──────────────────────────────▼──────────────────────────────┐
│                    FastAPI Python Backend                   │
│  ┌───────────────────────┐         ┌─────────────────────┐  │
│  │   Packet Analyzer     │         │      ML Engine      │  │
│  │  (Scapy IPsec/IKE)    │         │ (Isolation Forest)  │  │
│  └───────────┬───────────┘         └──────────┬──────────┘  │
│              │                                │             │
│  ┌───────────▼───────────┐         ┌──────────▼──────────┐  │
│  │   Security Scanner    │         │  Attack Simulator   │  │
│  │  (NIST SP 800-77/CIS) │         │ (6 Attack Vectors)  │  │
│  └───────────┬───────────┘         └──────────┬──────────┘  │
│              │                                │             │
│              └───────────────┬────────────────┘             │
│                              ▼                              │
│                 AI Report & Synthesis Engine                │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### Option 1: 1-Click Launch (Windows)
Double-click `start-all.bat` in the project root:
```cmd
start-all.bat
```
This launches both the FastAPI backend (port 8000) and the React frontend (port 3000) simultaneously.

### Option 2: Manual Launch

#### 1. Backend Server:
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
- API Documentation available at: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/api/health](http://localhost:8000/api/health)

#### 2. Frontend Application:
```bash
cd frontend
npm run dev -- --port 3000
```
- Open browser at: [http://localhost:3000](http://localhost:3000)

---

## 📊 Live Demo Scenarios Built-In

You can present three pre-configured enterprise VPN profiles without needing live physical gateways:

1. **Corporate VPN (`corporate_vpn`)**: Standard enterprise IPsec tunnel with balanced AES-CBC/GCM transforms and moderate risk indicators.
2. **Compromised Tunnel (`compromised_tunnel`)**: Live attack vector featuring active replay attacks, low-entropy exfiltration, and IKE flood probing.
3. **Site-to-Site VPN (`site_to_site`)**: Legacy inter-datacenter link using deprecated 3DES ciphers and IKEv1 Aggressive Mode.

Switch between scenarios instantly using the header dropdown or upload any real Wireshark `.pcap` / `.pcapng` file.

---

## 🏆 Presentation Workflow for SIH Judges

1. **Overview & Dashboard**: Showcase the real-time security gauge, protocol distribution (ESP vs AH vs IKE), and live telemetry.
2. **Protocol Deep Inspection**: Navigate to **Protocol Analyzer**, inspect individual ESP headers, examine SPIs (`0x8f2a11b0`), sequence numbers, and view the raw encrypted frame hex dump.
3. **Machine Learning Anomaly Engine**: Open **ML Anomaly Detector**, explain how unsupervised Isolation Forest detects zero-day tampering without decrypting user payloads, and demonstrate the feature importance weights.
4. **Security & Cryptographic Audit**: Show the **Security Assessment** tab, pointing out the NIST SP 800-77 compliance score, SWEET32/3DES vulnerability flags, and cleartext PSK risks.
5. **Adversarial Attack Simulation**: Jump to **Attack Simulator**, trigger the *IPsec Packet Replay Attack* or *IKE Downgrade Attack*, observe the step-by-step trace, and highlight the automated remediation recommendation.
6. **Executive AI Report**: Go to **AI Security Reports**, demonstrate the AI-synthesized audit summary, and click **Export JSON** to show export capabilities.
