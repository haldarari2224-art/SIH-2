"""
IPsec/VPN Security Scanner
Audits cryptographic configurations, detects vulnerabilities,
and generates compliance scores against NIST/CIS benchmarks.
"""

from datetime import datetime


# Vulnerability database
VULNERABILITY_DB = [
    {
        "id": "IPSEC-001",
        "title": "Weak Encryption Algorithm (DES)",
        "severity": "critical",
        "cve": "CVE-2016-2183",
        "description": "DES uses a 56-bit key, easily brute-forced by modern hardware in hours.",
        "remediation": "Replace DES with AES-256-GCM or ChaCha20-Poly1305.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("encryption") == "DES-CBC",
    },
    {
        "id": "IPSEC-002",
        "title": "Weak Encryption Algorithm (3DES)",
        "severity": "high",
        "cve": "CVE-2016-2183",
        "description": "3DES is vulnerable to the Sweet32 birthday attack on 64-bit block ciphers.",
        "remediation": "Migrate to AES-128-GCM or AES-256-GCM.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("encryption") == "3DES-CBC",
    },
    {
        "id": "IPSEC-003",
        "title": "NULL Encryption Detected",
        "severity": "critical",
        "cve": None,
        "description": "Traffic is transmitted without any encryption, exposing all data in cleartext.",
        "remediation": "Enable AES-256-GCM encryption on all IPsec Security Associations.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("encryption") == "NULL",
    },
    {
        "id": "IPSEC-004",
        "title": "Weak Hash Algorithm (MD5)",
        "severity": "high",
        "cve": "CVE-2004-2761",
        "description": "MD5 is cryptographically broken and susceptible to collision attacks.",
        "remediation": "Use SHA-256 or SHA-384 for integrity verification.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("hash_algorithm") == "MD5",
    },
    {
        "id": "IPSEC-005",
        "title": "Deprecated Hash Algorithm (SHA-1)",
        "severity": "medium",
        "cve": "CVE-2005-4900",
        "description": "SHA-1 has known collision vulnerabilities and is deprecated by NIST since 2011.",
        "remediation": "Upgrade to SHA-256 or higher for all IPsec operations.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("hash_algorithm") == "SHA-1",
    },
    {
        "id": "IPSEC-006",
        "title": "IKE Aggressive Mode Detected",
        "severity": "high",
        "cve": None,
        "description": "Aggressive Mode transmits identity in cleartext, enabling offline PSK dictionary attacks.",
        "remediation": "Switch to IKE Main Mode or IKEv2 which protects identity information.",
        "category": "configuration",
        "triggers": lambda pkt: pkt.get("ike_mode") == "Aggressive",
    },
    {
        "id": "IPSEC-007",
        "title": "Perfect Forward Secrecy Disabled",
        "severity": "high",
        "cve": None,
        "description": "Without PFS, compromise of the long-term key exposes all past session data.",
        "remediation": "Enable PFS with Diffie-Hellman Group 19 (ECP-256) or higher.",
        "category": "configuration",
        "triggers": lambda pkt: pkt.get("pfs_enabled") is False,
    },
    {
        "id": "IPSEC-008",
        "title": "Weak Diffie-Hellman Group",
        "severity": "high",
        "cve": "CVE-2015-4000",
        "description": "DH Groups 1, 2, and 5 use small moduli vulnerable to the Logjam attack.",
        "remediation": "Use DH Group 19 (ECP-256) or Group 20 (ECP-384) for key exchange.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("dh_group", "").startswith(("Group 1", "Group 2", "Group 5")),
    },
    {
        "id": "IPSEC-009",
        "title": "Short SA Lifetime",
        "severity": "low",
        "cve": None,
        "description": "SA lifetime under 1 hour causes excessive rekeying, increasing attack surface during negotiations.",
        "remediation": "Set SA lifetime to 8-24 hours for a balance of security and performance.",
        "category": "configuration",
        "triggers": lambda pkt: pkt.get("sa_lifetime") is not None and pkt.get("sa_lifetime") < 3600,
    },
    {
        "id": "IPSEC-010",
        "title": "Excessive SA Lifetime",
        "severity": "medium",
        "cve": None,
        "description": "SA lifetime exceeding 24 hours means compromised keys remain valid for too long.",
        "remediation": "Reduce SA lifetime to 8 hours maximum for Phase 2 SAs.",
        "category": "configuration",
        "triggers": lambda pkt: pkt.get("sa_lifetime") is not None and pkt.get("sa_lifetime") > 86400,
    },
    {
        "id": "IPSEC-011",
        "title": "Weak Encryption Key Size",
        "severity": "medium",
        "cve": None,
        "description": "Key sizes below 128 bits do not provide adequate security against brute-force attacks.",
        "remediation": "Use minimum 128-bit keys (AES-128) or preferably 256-bit keys (AES-256).",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("encryption_key_size", 256) < 128 and pkt.get("encryption_key_size", 256) > 0,
    },
    {
        "id": "IPSEC-012",
        "title": "RC4 Cipher Detected",
        "severity": "critical",
        "cve": "CVE-2015-2808",
        "description": "RC4 has multiple confirmed biases making it cryptographically broken.",
        "remediation": "Remove RC4 from all cipher suites immediately. Use AES-GCM.",
        "category": "cryptographic",
        "triggers": lambda pkt: pkt.get("encryption") == "RC4",
    },
]

# NIST / CIS Benchmark checks
COMPLIANCE_CHECKS = [
    {"id": "CIS-1", "name": "Strong Encryption Required", "description": "All tunnels use AES-128 or stronger", "category": "Encryption"},
    {"id": "CIS-2", "name": "Strong Hashing Required", "description": "All tunnels use SHA-256 or stronger", "category": "Integrity"},
    {"id": "CIS-3", "name": "PFS Enabled", "description": "Perfect Forward Secrecy is enabled on all tunnels", "category": "Key Exchange"},
    {"id": "CIS-4", "name": "IKEv2 Preferred", "description": "IKEv2 is used over IKEv1 for improved security", "category": "Protocol"},
    {"id": "CIS-5", "name": "No Aggressive Mode", "description": "IKE Aggressive Mode is disabled", "category": "Protocol"},
    {"id": "CIS-6", "name": "Strong DH Groups", "description": "DH Group 14 or higher is used for key exchange", "category": "Key Exchange"},
    {"id": "CIS-7", "name": "Appropriate SA Lifetime", "description": "SA lifetime is between 1 and 24 hours", "category": "Configuration"},
    {"id": "CIS-8", "name": "Anti-Replay Protection", "description": "Sequence numbers are properly incremented", "category": "Protection"},
]


class SecurityScanner:
    """Scans IPsec/VPN configurations for vulnerabilities and compliance."""

    def __init__(self):
        self.scan_results = {}

    def scan(self, packets, session_id=None):
        """Run a full security scan on the packet set."""
        if not session_id:
            import hashlib
            session_id = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:12]

        vulnerabilities = self._find_vulnerabilities(packets)
        crypto_audit = self._audit_crypto(packets)
        compliance = self._check_compliance(packets)
        score, grade = self._calculate_score(vulnerabilities, compliance)

        result = {
            "session_id": session_id,
            "scan_timestamp": datetime.now().isoformat(),
            "total_packets_scanned": len(packets),
            "security_score": score,
            "security_grade": grade,
            "vulnerabilities": vulnerabilities,
            "vulnerability_summary": self._vulnerability_summary(vulnerabilities),
            "crypto_audit": crypto_audit,
            "compliance_checks": compliance,
            "compliance_rate": self._compliance_rate(compliance),
            "recommendations": self._generate_recommendations(vulnerabilities, compliance),
        }

        self.scan_results[session_id] = result
        return result

    def _find_vulnerabilities(self, packets):
        """Scan packets against vulnerability database."""
        found = {}

        for pkt in packets:
            for vuln in VULNERABILITY_DB:
                try:
                    if vuln["triggers"](pkt):
                        vuln_id = vuln["id"]
                        if vuln_id not in found:
                            found[vuln_id] = {
                                "id": vuln["id"],
                                "title": vuln["title"],
                                "severity": vuln["severity"],
                                "cve": vuln["cve"],
                                "description": vuln["description"],
                                "remediation": vuln["remediation"],
                                "category": vuln["category"],
                                "affected_packets": 0,
                                "first_seen": pkt.get("timestamp", ""),
                            }
                        found[vuln_id]["affected_packets"] += 1
                except Exception:
                    continue

        return sorted(found.values(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

    def _audit_crypto(self, packets):
        """Audit all cryptographic algorithms in use."""
        encryption_used = {}
        hash_used = {}
        dh_used = {}

        for pkt in packets:
            enc = pkt.get("encryption")
            if enc:
                if enc not in encryption_used:
                    encryption_used[enc] = {
                        "algorithm": enc,
                        "key_size": pkt.get("encryption_key_size", 0),
                        "secure": pkt.get("crypto_secure", True),
                        "rating": pkt.get("crypto_rating", "?"),
                        "count": 0,
                    }
                encryption_used[enc]["count"] += 1

            h = pkt.get("hash_algorithm")
            if h:
                secure = h in ["SHA-256", "SHA-384", "SHA-512"]
                if h not in hash_used:
                    hash_used[h] = {"algorithm": h, "secure": secure, "count": 0}
                hash_used[h]["count"] += 1

            dh = pkt.get("dh_group")
            if dh:
                secure = not dh.startswith(("Group 1", "Group 2", "Group 5"))
                if dh not in dh_used:
                    dh_used[dh] = {"group": dh, "secure": secure, "count": 0}
                dh_used[dh]["count"] += 1

        return {
            "encryption_algorithms": list(encryption_used.values()),
            "hash_algorithms": list(hash_used.values()),
            "dh_groups": list(dh_used.values()),
            "overall_crypto_health": self._crypto_health(encryption_used, hash_used),
        }

    def _crypto_health(self, encryption, hashing):
        """Calculate overall cryptographic health."""
        total = sum(e["count"] for e in encryption.values())
        if total == 0:
            return "unknown"
        secure = sum(e["count"] for e in encryption.values() if e.get("secure", True))
        ratio = secure / total
        if ratio >= 0.95: return "excellent"
        if ratio >= 0.80: return "good"
        if ratio >= 0.60: return "fair"
        return "poor"

    def _check_compliance(self, packets):
        """Check against CIS/NIST benchmark items."""
        results = []

        has_weak_enc = any(not pkt.get("crypto_secure", True) for pkt in packets)
        has_weak_hash = any(pkt.get("hash_algorithm") in ["MD5"] for pkt in packets)
        has_no_pfs = any(pkt.get("pfs_enabled") is False for pkt in packets)
        has_ikev1_only = all(pkt.get("protocol") != "IKEv2" for pkt in packets if pkt.get("protocol", "").startswith("IKE"))
        has_aggressive = any(pkt.get("ike_mode") == "Aggressive" for pkt in packets)
        has_weak_dh = any(pkt.get("dh_group", "").startswith(("Group 1", "Group 2", "Group 5")) for pkt in packets)
        sa_lifetimes = [pkt.get("sa_lifetime") for pkt in packets if pkt.get("sa_lifetime") is not None]
        has_bad_lifetime = any(lt < 3600 or lt > 86400 for lt in sa_lifetimes) if sa_lifetimes else False

        # Check for sequence anomalies
        sequences = [pkt.get("sequence_number", 0) for pkt in packets if pkt.get("sequence_number")]
        has_seq_issues = len(sequences) != len(set(sequences)) if sequences else False

        check_map = {
            "CIS-1": not has_weak_enc,
            "CIS-2": not has_weak_hash,
            "CIS-3": not has_no_pfs,
            "CIS-4": not has_ikev1_only,
            "CIS-5": not has_aggressive,
            "CIS-6": not has_weak_dh,
            "CIS-7": not has_bad_lifetime,
            "CIS-8": not has_seq_issues,
        }

        for check in COMPLIANCE_CHECKS:
            passed = check_map.get(check["id"], True)
            results.append({
                **check,
                "status": "pass" if passed else "fail",
            })

        return results

    def _compliance_rate(self, checks):
        """Calculate compliance pass rate."""
        if not checks:
            return 0
        passed = sum(1 for c in checks if c["status"] == "pass")
        return round(passed / len(checks) * 100, 1)

    def _calculate_score(self, vulnerabilities, compliance):
        """Calculate overall security score (0-100)."""
        score = 100

        severity_penalty = {"critical": 15, "high": 10, "medium": 5, "low": 2}
        for vuln in vulnerabilities:
            score -= severity_penalty.get(vuln["severity"], 1)

        # Compliance penalty
        failed = sum(1 for c in compliance if c["status"] == "fail")
        score -= failed * 5

        score = max(0, min(100, score))

        if score >= 90: grade = "A+"
        elif score >= 80: grade = "A"
        elif score >= 70: grade = "B"
        elif score >= 60: grade = "C"
        elif score >= 50: grade = "D"
        else: grade = "F"

        return score, grade

    def _vulnerability_summary(self, vulnerabilities):
        """Summarize vulnerabilities by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            summary[v["severity"]] = summary.get(v["severity"], 0) + 1
        return summary

    def _generate_recommendations(self, vulnerabilities, compliance):
        """Generate prioritized security recommendations."""
        recs = []
        priority = 1

        # From vulnerabilities
        for vuln in vulnerabilities:
            if vuln["severity"] in ["critical", "high"]:
                recs.append({
                    "priority": priority,
                    "severity": vuln["severity"],
                    "title": f"Fix: {vuln['title']}",
                    "description": vuln["remediation"],
                    "reference": vuln.get("cve", ""),
                })
                priority += 1

        # From failed compliance
        for check in compliance:
            if check["status"] == "fail":
                recs.append({
                    "priority": priority,
                    "severity": "medium",
                    "title": f"Compliance: {check['name']}",
                    "description": check["description"],
                    "reference": check["id"],
                })
                priority += 1

        return recs[:10]  # Top 10 recommendations

    def get_scan_result(self, session_id):
        """Retrieve stored scan result."""
        return self.scan_results.get(session_id)
