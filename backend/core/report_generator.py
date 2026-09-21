"""
AI-Powered Report Generator
Generates comprehensive security assessment reports with
natural-language descriptions, severity ratings, and remediation steps.
"""

from datetime import datetime


class ReportGenerator:
    """Generates detailed security reports from analysis results."""

    def generate_full_report(self, session_id, analysis=None, scan=None, ml_results=None, simulation=None):
        """Generate a comprehensive security assessment report."""
        report = {
            "report_id": f"RPT-{session_id}",
            "generated_at": datetime.now().isoformat(),
            "report_type": "Full Security Assessment",
            "version": "1.0",
            "executive_summary": self._executive_summary(analysis, scan, ml_results, simulation),
            "sections": [],
        }

        # Section 1: Traffic Analysis Overview
        if analysis:
            report["sections"].append(self._traffic_section(analysis))

        # Section 2: Anomaly Detection Findings
        if ml_results:
            report["sections"].append(self._anomaly_section(ml_results))

        # Section 3: Security Vulnerabilities
        if scan:
            report["sections"].append(self._vulnerability_section(scan))

        # Section 4: Cryptographic Assessment
        if scan and "crypto_audit" in scan:
            report["sections"].append(self._crypto_section(scan))

        # Section 5: Compliance Status
        if scan and "compliance_checks" in scan:
            report["sections"].append(self._compliance_section(scan))

        # Section 6: Attack Simulation Results
        if simulation:
            report["sections"].append(self._attack_section(simulation))

        # Section 7: Recommendations
        report["sections"].append(self._recommendations_section(scan, ml_results, simulation))

        # Risk Summary
        report["risk_summary"] = self._risk_summary(scan, ml_results, simulation)

        return report

    def _executive_summary(self, analysis, scan, ml_results, simulation):
        """Generate executive summary."""
        score = scan.get("security_score", 0) if scan else 50
        grade = scan.get("security_grade", "N/A") if scan else "N/A"
        total_packets = analysis.get("total_packets", 0) if analysis else 0
        anomalies = ml_results.get("total_anomalies", 0) if ml_results else 0
        vulns = len(scan.get("vulnerabilities", [])) if scan else 0
        vuln_attacks = simulation.get("vulnerable_count", 0) if simulation else 0

        # Determine overall risk level
        if score >= 80:
            risk_level = "LOW"
            risk_description = "The analyzed IPsec/VPN configuration demonstrates a strong security posture with minor issues."
        elif score >= 60:
            risk_level = "MODERATE"
            risk_description = "The configuration has notable security gaps that should be addressed to prevent potential exploitation."
        elif score >= 40:
            risk_level = "HIGH"
            risk_description = "Critical vulnerabilities have been identified that pose significant risk to data confidentiality and integrity."
        else:
            risk_level = "CRITICAL"
            risk_description = "The VPN configuration contains severe security flaws requiring immediate remediation."

        return {
            "security_score": score,
            "security_grade": grade,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "key_findings": [
                f"Analyzed {total_packets} IPsec packets across the capture session",
                f"Detected {anomalies} anomalous traffic patterns using ML-based analysis",
                f"Identified {vulns} security vulnerabilities in the VPN configuration",
                f"Simulated {vuln_attacks} successful attack scenarios out of {simulation.get('total_attacks_tested', 0) if simulation else 0} tested",
                f"Overall security score: {score}/100 (Grade: {grade})",
            ],
            "immediate_actions": self._get_immediate_actions(scan, simulation),
        }

    def _get_immediate_actions(self, scan, simulation):
        """Get list of immediate actions needed."""
        actions = []
        if scan:
            for vuln in scan.get("vulnerabilities", []):
                if vuln["severity"] == "critical":
                    actions.append(f"🔴 CRITICAL: {vuln['title']} — {vuln['remediation']}")
            for vuln in scan.get("vulnerabilities", []):
                if vuln["severity"] == "high" and len(actions) < 5:
                    actions.append(f"🟠 HIGH: {vuln['title']} — {vuln['remediation']}")

        if simulation:
            for result in simulation.get("attack_results", []):
                if result["vulnerable"] and result["risk_level"] == "critical" and len(actions) < 7:
                    actions.append(f"⚠️ ATTACK RISK: {result['name']} — {result['remediation'][0] if result['remediation'] else 'Review configuration'}")

        return actions[:7] if actions else ["No critical actions required — maintain current security posture"]

    def _traffic_section(self, analysis):
        """Generate traffic analysis section."""
        return {
            "title": "Traffic Analysis Overview",
            "icon": "📊",
            "content": {
                "total_packets": analysis.get("total_packets", 0),
                "ipsec_packets": analysis.get("ipsec_packets", 0),
                "source": analysis.get("source", "unknown"),
                "protocol_distribution": analysis.get("protocol_summary", {}),
                "top_flows": analysis.get("flow_summary", [])[:5],
                "analysis": f"Captured and analyzed {analysis.get('total_packets', 0)} packets. "
                           f"IPsec traffic constitutes {analysis.get('ipsec_packets', 0)} packets across "
                           f"ESP, AH, and IKE protocols.",
            },
        }

    def _anomaly_section(self, ml_results):
        """Generate anomaly detection section."""
        return {
            "title": "Anomaly Detection Findings",
            "icon": "🔍",
            "content": {
                "total_analyzed": ml_results.get("total_analyzed", 0),
                "total_anomalies": ml_results.get("total_anomalies", 0),
                "anomaly_rate": ml_results.get("anomaly_rate", 0),
                "severity_distribution": ml_results.get("severity_distribution", {}),
                "type_distribution": ml_results.get("anomaly_type_distribution", {}),
                "top_anomalies": ml_results.get("anomalies", [])[:10],
                "model_info": ml_results.get("model_info", {}),
                "analysis": f"Machine learning analysis detected {ml_results.get('total_anomalies', 0)} "
                           f"anomalous packets ({ml_results.get('anomaly_rate', 0)}% of total traffic). "
                           f"Analysis used Isolation Forest and Random Forest models trained on IPsec traffic patterns.",
            },
        }

    def _vulnerability_section(self, scan):
        """Generate vulnerability section."""
        vulns = scan.get("vulnerabilities", [])
        return {
            "title": "Security Vulnerabilities",
            "icon": "🛡️",
            "content": {
                "total_vulnerabilities": len(vulns),
                "summary": scan.get("vulnerability_summary", {}),
                "vulnerabilities": vulns,
                "analysis": f"Security scan identified {len(vulns)} vulnerabilities: "
                           f"{scan.get('vulnerability_summary', {}).get('critical', 0)} critical, "
                           f"{scan.get('vulnerability_summary', {}).get('high', 0)} high, "
                           f"{scan.get('vulnerability_summary', {}).get('medium', 0)} medium, "
                           f"{scan.get('vulnerability_summary', {}).get('low', 0)} low severity.",
            },
        }

    def _crypto_section(self, scan):
        """Generate cryptographic assessment section."""
        audit = scan.get("crypto_audit", {})
        return {
            "title": "Cryptographic Assessment",
            "icon": "🔐",
            "content": {
                "encryption_algorithms": audit.get("encryption_algorithms", []),
                "hash_algorithms": audit.get("hash_algorithms", []),
                "dh_groups": audit.get("dh_groups", []),
                "overall_health": audit.get("overall_crypto_health", "unknown"),
                "analysis": f"Cryptographic audit reveals {audit.get('overall_crypto_health', 'unknown')} "
                           f"overall health. Found {len(audit.get('encryption_algorithms', []))} encryption algorithms, "
                           f"{len(audit.get('hash_algorithms', []))} hash algorithms, and "
                           f"{len(audit.get('dh_groups', []))} Diffie-Hellman groups in use.",
            },
        }

    def _compliance_section(self, scan):
        """Generate compliance section."""
        checks = scan.get("compliance_checks", [])
        return {
            "title": "Compliance Status (NIST/CIS)",
            "icon": "✅",
            "content": {
                "compliance_rate": scan.get("compliance_rate", 0),
                "checks": checks,
                "passed": sum(1 for c in checks if c["status"] == "pass"),
                "failed": sum(1 for c in checks if c["status"] == "fail"),
                "total": len(checks),
                "analysis": f"Compliance check against CIS/NIST benchmarks: "
                           f"{sum(1 for c in checks if c['status'] == 'pass')}/{len(checks)} checks passed "
                           f"({scan.get('compliance_rate', 0)}% compliance rate).",
            },
        }

    def _attack_section(self, simulation):
        """Generate attack simulation section."""
        results = simulation.get("attack_results", [])
        return {
            "title": "Attack Simulation Results",
            "icon": "⚔️",
            "content": {
                "total_tested": simulation.get("total_attacks_tested", 0),
                "vulnerable": simulation.get("vulnerable_count", 0),
                "resilience_score": simulation.get("resilience_score", 0),
                "resilience_grade": simulation.get("resilience_grade", "N/A"),
                "risk_matrix": simulation.get("risk_matrix", {}),
                "attack_details": results,
                "analysis": f"Simulated {len(results)} attack scenarios. "
                           f"Configuration is vulnerable to {simulation.get('vulnerable_count', 0)} attacks. "
                           f"Overall resilience score: {simulation.get('resilience_score', 0)}%.",
            },
        }

    def _recommendations_section(self, scan, ml_results, simulation):
        """Generate prioritized recommendations."""
        recs = []
        if scan:
            recs.extend(scan.get("recommendations", []))

        return {
            "title": "Recommendations",
            "icon": "💡",
            "content": {
                "recommendations": recs,
                "total": len(recs),
                "analysis": f"Generated {len(recs)} prioritized security recommendations "
                           f"based on vulnerability scan, anomaly detection, and attack simulation results.",
            },
        }

    def _risk_summary(self, scan, ml_results, simulation):
        """Generate overall risk summary."""
        scores = []
        if scan:
            scores.append(scan.get("security_score", 50))
        if simulation:
            scores.append(simulation.get("resilience_score", 50))

        avg_score = sum(scores) / len(scores) if scores else 50

        return {
            "overall_score": round(avg_score),
            "security_scan_score": scan.get("security_score", None) if scan else None,
            "resilience_score": simulation.get("resilience_score", None) if simulation else None,
            "anomaly_rate": ml_results.get("anomaly_rate", None) if ml_results else None,
        }
