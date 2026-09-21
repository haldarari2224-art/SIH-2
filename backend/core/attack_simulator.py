"""
Attack Simulator
Simulates common IPsec/VPN attacks (safely, no real attacks)
to assess the security posture of a VPN configuration.
"""

import random
from datetime import datetime


ATTACK_TYPES = {
    "replay_attack": {
        "name": "Replay Attack",
        "description": "Captures and retransmits valid IPsec packets to disrupt or duplicate sessions.",
        "impact": "high",
        "difficulty": "medium",
        "category": "integrity",
        "mitre_id": "T1557",
    },
    "downgrade_attack": {
        "name": "Cipher Suite Downgrade",
        "description": "Forces negotiation of weaker cryptographic algorithms during IKE handshake.",
        "impact": "critical",
        "difficulty": "medium",
        "category": "cryptographic",
        "mitre_id": "T1565",
    },
    "spi_spoofing": {
        "name": "SPI Spoofing",
        "description": "Forges Security Parameter Index values to inject unauthorized packets into an IPsec tunnel.",
        "impact": "high",
        "difficulty": "high",
        "category": "authentication",
        "mitre_id": "T1557.002",
    },
    "ike_flood": {
        "name": "IKE Negotiation Flood (DDoS)",
        "description": "Floods the VPN gateway with IKE_SA_INIT requests to exhaust resources.",
        "impact": "high",
        "difficulty": "low",
        "category": "availability",
        "mitre_id": "T1498",
    },
    "mitm_attack": {
        "name": "Man-in-the-Middle (IKE)",
        "description": "Intercepts IKE handshake to capture pre-shared keys or manipulate SA negotiation.",
        "impact": "critical",
        "difficulty": "high",
        "category": "confidentiality",
        "mitre_id": "T1557.001",
    },
    "certificate_forgery": {
        "name": "Certificate Forgery",
        "description": "Uses forged or stolen certificates to authenticate to the VPN gateway.",
        "impact": "critical",
        "difficulty": "high",
        "category": "authentication",
        "mitre_id": "T1649",
    },
}


class AttackSimulator:
    """Simulates attacks against IPsec/VPN configurations for security assessment."""

    def __init__(self):
        self.simulation_results = {}

    def simulate_all(self, packets, session_id=None):
        """Run all attack simulations against the given traffic/config."""
        import hashlib
        if not session_id:
            session_id = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:12]

        config = self._extract_config(packets)
        results = []

        for attack_id, attack_info in ATTACK_TYPES.items():
            result = self._simulate_attack(attack_id, attack_info, config, packets)
            results.append(result)

        # Build risk matrix
        risk_matrix = self._build_risk_matrix(results)

        # Overall resilience score
        resilience_score = self._calculate_resilience(results)

        simulation = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "config_summary": config,
            "attack_results": results,
            "risk_matrix": risk_matrix,
            "resilience_score": resilience_score,
            "resilience_grade": self._score_to_grade(resilience_score),
            "total_attacks_tested": len(results),
            "vulnerable_count": sum(1 for r in results if r["vulnerable"]),
            "safe_count": sum(1 for r in results if not r["vulnerable"]),
        }

        self.simulation_results[session_id] = simulation
        return simulation

    def simulate_single(self, attack_type, packets, session_id=None):
        """Run a single attack simulation."""
        if attack_type not in ATTACK_TYPES:
            return {"error": f"Unknown attack type: {attack_type}"}

        config = self._extract_config(packets)
        attack_info = ATTACK_TYPES[attack_type]
        result = self._simulate_attack(attack_type, attack_info, config, packets)

        return {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "attack_result": result,
        }

    def _extract_config(self, packets):
        """Extract VPN configuration from packet metadata."""
        encryptions = set()
        hashes = set()
        dh_groups = set()
        modes = set()
        pfs_values = set()
        sa_lifetimes = []

        for pkt in packets:
            if pkt.get("encryption"):
                encryptions.add(pkt["encryption"])
            if pkt.get("hash_algorithm"):
                hashes.add(pkt["hash_algorithm"])
            if pkt.get("dh_group"):
                dh_groups.add(pkt["dh_group"])
            if pkt.get("ike_mode"):
                modes.add(pkt["ike_mode"])
            if pkt.get("pfs_enabled") is not None:
                pfs_values.add(pkt["pfs_enabled"])
            if pkt.get("sa_lifetime"):
                sa_lifetimes.append(pkt["sa_lifetime"])

        return {
            "encryptions": list(encryptions),
            "hashes": list(hashes),
            "dh_groups": list(dh_groups),
            "ike_modes": list(modes),
            "pfs_enabled": True in pfs_values,
            "has_weak_crypto": any(e in ["DES-CBC", "3DES-CBC", "RC4", "NULL"] for e in encryptions),
            "has_weak_hash": "MD5" in hashes,
            "has_aggressive_mode": "Aggressive" in modes,
            "avg_sa_lifetime": sum(sa_lifetimes) / len(sa_lifetimes) if sa_lifetimes else 28800,
        }

    def _simulate_attack(self, attack_id, attack_info, config, packets):
        """Simulate a specific attack type."""
        vulnerable = False
        success_probability = 0
        attack_steps = []
        remediation_steps = []

        if attack_id == "replay_attack":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_replay(config, packets)
        elif attack_id == "downgrade_attack":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_downgrade(config)
        elif attack_id == "spi_spoofing":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_spi_spoof(config, packets)
        elif attack_id == "ike_flood":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_ike_flood(config)
        elif attack_id == "mitm_attack":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_mitm(config)
        elif attack_id == "certificate_forgery":
            vulnerable, success_probability, attack_steps, remediation_steps = self._sim_cert_forgery(config)

        return {
            "attack_id": attack_id,
            "name": attack_info["name"],
            "description": attack_info["description"],
            "impact": attack_info["impact"],
            "difficulty": attack_info["difficulty"],
            "category": attack_info["category"],
            "mitre_id": attack_info["mitre_id"],
            "vulnerable": vulnerable,
            "success_probability": success_probability,
            "risk_level": self._calc_risk(attack_info["impact"], success_probability),
            "attack_steps": attack_steps,
            "remediation": remediation_steps,
        }

    def _sim_replay(self, config, packets):
        # Check for sequence number reuse
        seq_numbers = [p.get("sequence_number", 0) for p in packets if p.get("sequence_number")]
        has_duplicates = len(seq_numbers) != len(set(seq_numbers))
        has_weak_seq = any(s < 5 for s in seq_numbers)

        vulnerable = has_duplicates or has_weak_seq
        prob = 65 if vulnerable else 10

        steps = [
            {"step": 1, "action": "Capture IPsec ESP packets from the network", "status": "simulated"},
            {"step": 2, "action": "Extract SPI and sequence numbers from ESP headers", "status": "simulated"},
            {"step": 3, "action": "Check anti-replay window configuration", "status": "vulnerable" if vulnerable else "blocked"},
            {"step": 4, "action": "Retransmit captured packet with original sequence number", "status": "success" if vulnerable else "rejected"},
        ]

        remediation = [
            "Enable anti-replay protection on all Security Associations",
            "Use a sliding window size of at least 64 packets",
            "Implement strict sequence number validation",
            "Monitor for duplicate sequence numbers in real-time",
        ]

        return vulnerable, prob, steps, remediation

    def _sim_downgrade(self, config):
        vulnerable = config["has_weak_crypto"] or config["has_weak_hash"]
        prob = 75 if vulnerable else 5

        steps = [
            {"step": 1, "action": "Intercept IKE_SA_INIT exchange", "status": "simulated"},
            {"step": 2, "action": "Modify proposed cipher suites to include weak algorithms", "status": "simulated"},
            {"step": 3, "action": "Check if responder accepts deprecated ciphers", "status": "vulnerable" if vulnerable else "blocked"},
            {"step": 4, "action": "Force negotiation to DES/3DES/MD5", "status": "success" if vulnerable else "rejected"},
        ]

        remediation = [
            "Remove all weak cipher suites (DES, 3DES, RC4, NULL) from proposals",
            "Enforce minimum AES-128 for encryption and SHA-256 for integrity",
            "Use IKEv2 which has built-in downgrade protection",
            "Implement cipher suite pinning in VPN gateway configuration",
        ]

        return vulnerable, prob, steps, remediation

    def _sim_spi_spoof(self, config, packets):
        spis = [p.get("spi") for p in packets if p.get("spi")]
        unique_spis = set(spis)
        low_spis = any(int(s, 16) < 256 for s in spis if s)

        vulnerable = low_spis or len(unique_spis) < 3
        prob = 45 if vulnerable else 8

        steps = [
            {"step": 1, "action": "Observe SPI values in ESP/AH headers", "status": "simulated"},
            {"step": 2, "action": "Analyze SPI randomness and range", "status": "simulated"},
            {"step": 3, "action": "Attempt to predict or guess valid SPI", "status": "vulnerable" if vulnerable else "blocked"},
            {"step": 4, "action": "Inject packet with forged SPI", "status": "success" if vulnerable else "rejected"},
        ]

        remediation = [
            "Use cryptographically random SPI generation",
            "Ensure SPI values are sufficiently large (> 256)",
            "Implement SPI validation against known Security Associations",
            "Monitor for packets with unknown SPI values",
        ]

        return vulnerable, prob, steps, remediation

    def _sim_ike_flood(self, config):
        vulnerable = config.get("has_aggressive_mode", False)
        prob = 55 if vulnerable else 20

        steps = [
            {"step": 1, "action": "Generate high volume of IKE_SA_INIT requests", "status": "simulated"},
            {"step": 2, "action": "Target VPN gateway UDP port 500/4500", "status": "simulated"},
            {"step": 3, "action": "Check rate limiting and cookie challenge", "status": "vulnerable" if vulnerable else "mitigated"},
            {"step": 4, "action": "Attempt to exhaust gateway resources", "status": "partial" if vulnerable else "blocked"},
        ]

        remediation = [
            "Enable IKEv2 cookie challenge mechanism",
            "Implement rate limiting on IKE negotiations (max 50/sec per source)",
            "Deploy DDoS protection at the network edge",
            "Use IKEv2 instead of IKEv1 for better flood resistance",
        ]

        return vulnerable, prob, steps, remediation

    def _sim_mitm(self, config):
        vulnerable = config["has_aggressive_mode"] and not config["pfs_enabled"]
        prob = 40 if vulnerable else 3

        steps = [
            {"step": 1, "action": "Position attacker between VPN peers (ARP spoofing)", "status": "simulated"},
            {"step": 2, "action": "Intercept IKE handshake messages", "status": "simulated"},
            {"step": 3, "action": "Attempt to extract identity/PSK from Aggressive Mode", "status": "vulnerable" if vulnerable else "encrypted"},
            {"step": 4, "action": "Forge IKE responses to establish rogue tunnel", "status": "success" if vulnerable else "rejected"},
        ]

        remediation = [
            "Use certificate-based authentication instead of PSK",
            "Switch from IKEv1 Aggressive Mode to IKEv2",
            "Enable PFS for all security associations",
            "Implement mutual authentication between VPN peers",
        ]

        return vulnerable, prob, steps, remediation

    def _sim_cert_forgery(self, config):
        vulnerable = config["has_weak_hash"]  # MD5 certs can be forged
        prob = 30 if vulnerable else 2

        steps = [
            {"step": 1, "action": "Obtain a valid certificate from the PKI", "status": "simulated"},
            {"step": 2, "action": "Analyze certificate signing algorithm", "status": "simulated"},
            {"step": 3, "action": "Attempt MD5 collision to forge certificate", "status": "vulnerable" if vulnerable else "infeasible"},
            {"step": 4, "action": "Present forged certificate during IKE auth", "status": "success" if vulnerable else "rejected"},
        ]

        remediation = [
            "Use SHA-256 or stronger for certificate signatures",
            "Implement Certificate Revocation List (CRL) checking",
            "Pin trusted CA certificates on VPN gateways",
            "Use short-lived certificates with automated rotation",
        ]

        return vulnerable, prob, steps, remediation

    def _calc_risk(self, impact, probability):
        impact_score = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(impact, 1)
        prob_score = 4 if probability > 60 else 3 if probability > 40 else 2 if probability > 20 else 1
        risk = impact_score * prob_score
        if risk >= 12: return "critical"
        if risk >= 8: return "high"
        if risk >= 4: return "medium"
        return "low"

    def _build_risk_matrix(self, results):
        """Build impact vs likelihood risk matrix."""
        matrix = {
            "critical_high": [],
            "critical_medium": [],
            "critical_low": [],
            "high_high": [],
            "high_medium": [],
            "high_low": [],
            "medium_high": [],
            "medium_medium": [],
            "medium_low": [],
        }

        for r in results:
            impact = r["impact"]
            if r["success_probability"] > 50:
                likelihood = "high"
            elif r["success_probability"] > 20:
                likelihood = "medium"
            else:
                likelihood = "low"

            key = f"{impact}_{likelihood}"
            if key in matrix:
                matrix[key].append(r["name"])

        return matrix

    def _calculate_resilience(self, results):
        """Calculate overall resilience score."""
        if not results:
            return 100
        safe = sum(1 for r in results if not r["vulnerable"])
        return round(safe / len(results) * 100)

    def _score_to_grade(self, score):
        if score >= 90: return "A+"
        if score >= 80: return "A"
        if score >= 70: return "B"
        if score >= 60: return "C"
        if score >= 50: return "D"
        return "F"

    def get_available_attacks(self):
        """Return available attack types."""
        return {k: {kk: vv for kk, vv in v.items()} for k, v in ATTACK_TYPES.items()}

    def get_result(self, session_id):
        """Retrieve stored simulation result."""
        return self.simulation_results.get(session_id)
