"""
Demo Data Generator
Generates realistic synthetic IPsec/VPN traffic data for demonstration purposes.
Includes normal flows, planted anomalies, and multiple scenario profiles.
"""

import random
import time
import hashlib
from datetime import datetime, timedelta


# Encryption algorithms with security ratings
CRYPTO_ALGORITHMS = {
    "strong": [
        {"name": "AES-256-GCM", "key_size": 256, "rating": "A+", "secure": True},
        {"name": "AES-128-GCM", "key_size": 128, "rating": "A", "secure": True},
        {"name": "ChaCha20-Poly1305", "key_size": 256, "rating": "A+", "secure": True},
    ],
    "moderate": [
        {"name": "AES-128-CBC", "key_size": 128, "rating": "B", "secure": True},
        {"name": "AES-256-CBC", "key_size": 256, "rating": "B+", "secure": True},
    ],
    "weak": [
        {"name": "3DES-CBC", "key_size": 168, "rating": "D", "secure": False},
        {"name": "DES-CBC", "key_size": 56, "rating": "F", "secure": False},
        {"name": "RC4", "key_size": 128, "rating": "F", "secure": False},
        {"name": "NULL", "key_size": 0, "rating": "F", "secure": False},
    ],
}

HASH_ALGORITHMS = {
    "strong": ["SHA-256", "SHA-384", "SHA-512"],
    "moderate": ["SHA-1"],
    "weak": ["MD5"],
}

DH_GROUPS = {
    "strong": ["Group 19 (ECP-256)", "Group 20 (ECP-384)", "Group 21 (ECP-521)"],
    "moderate": ["Group 14 (MODP-2048)", "Group 15 (MODP-3072)"],
    "weak": ["Group 1 (MODP-768)", "Group 2 (MODP-1024)", "Group 5 (MODP-1536)"],
}

ANOMALY_TYPES = [
    "replay_attack",
    "spi_spoofing",
    "flood_attack",
    "downgrade_attempt",
    "sequence_anomaly",
    "unusual_payload_size",
    "rogue_endpoint",
    "timing_anomaly",
]

SCENARIO_PROFILES = {
    "corporate_vpn": {
        "description": "Corporate VPN with mixed security posture",
        "src_networks": ["10.0.1.", "10.0.2.", "10.0.3."],
        "dst_networks": ["192.168.1.", "192.168.2."],
        "gateway_ips": ["203.0.113.1", "203.0.113.2"],
        "anomaly_rate": 0.08,
        "weak_crypto_rate": 0.15,
    },
    "site_to_site": {
        "description": "Site-to-Site VPN with strong security",
        "src_networks": ["172.16.0.", "172.16.1."],
        "dst_networks": ["172.17.0.", "172.17.1."],
        "gateway_ips": ["198.51.100.10", "198.51.100.20"],
        "anomaly_rate": 0.03,
        "weak_crypto_rate": 0.05,
    },
    "compromised_tunnel": {
        "description": "Tunnel under active attack with multiple threats",
        "src_networks": ["10.10.0.", "10.10.1."],
        "dst_networks": ["10.20.0.", "10.20.1."],
        "gateway_ips": ["198.18.0.1", "198.18.0.2"],
        "anomaly_rate": 0.25,
        "weak_crypto_rate": 0.40,
    },
}


def _random_ip(network_prefix):
    return f"{network_prefix}{random.randint(1, 254)}"


def _random_spi():
    return f"0x{random.randint(0x100, 0xFFFFFFFF):08x}"


def _random_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def generate_packet(timestamp, scenario, packet_id, is_anomaly=False, anomaly_type=None):
    """Generate a single synthetic IPsec packet."""
    profile = SCENARIO_PROFILES[scenario]
    src_net = random.choice(profile["src_networks"])
    dst_net = random.choice(profile["dst_networks"])

    # Decide protocol
    protocol_weights = {"ESP": 0.70, "AH": 0.10, "IKE": 0.15, "IKEv2": 0.05}
    protocol = random.choices(
        list(protocol_weights.keys()), weights=list(protocol_weights.values())
    )[0]

    # Crypto selection
    if random.random() < profile["weak_crypto_rate"]:
        crypto_category = random.choice(["weak", "moderate"])
    else:
        crypto_category = "strong"

    crypto = random.choice(CRYPTO_ALGORITHMS[crypto_category])
    hash_algo = random.choice(
        HASH_ALGORITHMS[crypto_category if crypto_category in HASH_ALGORITHMS else "strong"]
    )
    dh_group = random.choice(
        DH_GROUPS[crypto_category if crypto_category in DH_GROUPS else "strong"]
    )

    # Base packet
    packet = {
        "id": packet_id,
        "timestamp": timestamp.isoformat(),
        "timestamp_unix": timestamp.timestamp(),
        "src_ip": _random_ip(src_net),
        "dst_ip": _random_ip(dst_net),
        "src_mac": _random_mac(),
        "dst_mac": _random_mac(),
        "protocol": protocol,
        "mode": random.choice(["Tunnel", "Transport"]),
        "spi": _random_spi(),
        "sequence_number": random.randint(1, 100000),
        "payload_size": random.randint(64, 1400),
        "ttl": random.choice([64, 128, 255]),
        "encryption": crypto["name"],
        "encryption_key_size": crypto["key_size"],
        "crypto_rating": crypto["rating"],
        "crypto_secure": crypto["secure"],
        "hash_algorithm": hash_algo,
        "dh_group": dh_group,
        "gateway_ip": random.choice(profile["gateway_ips"]),
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type,
        "anomaly_severity": None,
        "anomaly_description": None,
    }

    # IKE-specific fields
    if protocol in ["IKE", "IKEv2"]:
        packet["ike_phase"] = random.choice([1, 2])
        packet["ike_mode"] = random.choice(["Main", "Aggressive", "Quick"])
        packet["ike_exchange_type"] = random.choice([
            "Identity Protection",
            "Aggressive",
            "Informational",
            "Quick Mode",
        ])
        packet["pfs_enabled"] = random.random() > 0.2
        packet["sa_lifetime"] = random.choice([3600, 7200, 28800, 86400])
    else:
        packet["ike_phase"] = None
        packet["ike_mode"] = None
        packet["ike_exchange_type"] = None
        packet["pfs_enabled"] = None
        packet["sa_lifetime"] = None

    # Inject anomaly characteristics
    if is_anomaly:
        packet = _inject_anomaly(packet, anomaly_type)

    # Generate features for ML
    packet["features"] = _extract_features(packet)

    return packet


def _inject_anomaly(packet, anomaly_type):
    """Inject anomaly-specific characteristics into a packet."""
    if anomaly_type == "replay_attack":
        packet["anomaly_severity"] = "critical"
        packet["anomaly_description"] = "Duplicate sequence number detected — potential replay attack"
        packet["sequence_number"] = random.choice([1, 2, 3])  # Suspiciously low/repeated

    elif anomaly_type == "spi_spoofing":
        packet["anomaly_severity"] = "high"
        packet["anomaly_description"] = "SPI value does not match any known Security Association"
        packet["spi"] = f"0x{random.randint(0x1, 0xFF):08x}"  # Unusually small SPI

    elif anomaly_type == "flood_attack":
        packet["anomaly_severity"] = "critical"
        packet["anomaly_description"] = "Abnormal burst of IKE negotiation requests — possible DDoS"
        packet["protocol"] = "IKE"
        packet["payload_size"] = random.randint(40, 80)  # Small flood packets

    elif anomaly_type == "downgrade_attempt":
        packet["anomaly_severity"] = "high"
        packet["anomaly_description"] = "Attempted negotiation of deprecated weak cipher suite"
        weak = random.choice(CRYPTO_ALGORITHMS["weak"])
        packet["encryption"] = weak["name"]
        packet["encryption_key_size"] = weak["key_size"]
        packet["crypto_rating"] = weak["rating"]
        packet["crypto_secure"] = False
        packet["hash_algorithm"] = "MD5"

    elif anomaly_type == "sequence_anomaly":
        packet["anomaly_severity"] = "medium"
        packet["anomaly_description"] = "Non-monotonic sequence number — possible packet injection"
        packet["sequence_number"] = random.randint(900000, 999999)

    elif anomaly_type == "unusual_payload_size":
        packet["anomaly_severity"] = "medium"
        packet["anomaly_description"] = "Payload size exceeds expected MTU — potential buffer overflow attempt"
        packet["payload_size"] = random.randint(9000, 65535)

    elif anomaly_type == "rogue_endpoint":
        packet["anomaly_severity"] = "critical"
        packet["anomaly_description"] = "Connection from unrecognized IP outside authorized network range"
        packet["src_ip"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    elif anomaly_type == "timing_anomaly":
        packet["anomaly_severity"] = "low"
        packet["anomaly_description"] = "Unusual inter-packet timing pattern — possible covert channel"

    return packet


def _extract_features(packet):
    """Extract numerical features for ML model input."""
    protocol_map = {"ESP": 0, "AH": 1, "IKE": 2, "IKEv2": 3}
    mode_map = {"Tunnel": 0, "Transport": 1}

    return {
        "protocol_encoded": protocol_map.get(packet["protocol"], 0),
        "mode_encoded": mode_map.get(packet["mode"], 0),
        "payload_size": packet["payload_size"],
        "ttl": packet["ttl"],
        "encryption_key_size": packet["encryption_key_size"],
        "crypto_secure": 1 if packet["crypto_secure"] else 0,
        "sequence_number": packet["sequence_number"],
        "spi_numeric": int(packet["spi"], 16),
        "is_ike": 1 if packet["protocol"] in ["IKE", "IKEv2"] else 0,
        "pfs_enabled": 1 if packet.get("pfs_enabled") else 0,
    }


def generate_traffic_session(
    scenario="corporate_vpn", num_packets=500, duration_minutes=30
):
    """Generate a full traffic session with mixed normal and anomalous packets."""
    profile = SCENARIO_PROFILES[scenario]
    packets = []
    start_time = datetime.now() - timedelta(minutes=duration_minutes)

    for i in range(num_packets):
        # Distribute timestamps across the session duration
        offset_seconds = (duration_minutes * 60 / num_packets) * i
        offset_seconds += random.uniform(-2, 2)  # jitter
        timestamp = start_time + timedelta(seconds=max(0, offset_seconds))

        # Decide if this packet is anomalous
        is_anomaly = random.random() < profile["anomaly_rate"]
        anomaly_type = random.choice(ANOMALY_TYPES) if is_anomaly else None

        packet = generate_packet(
            timestamp=timestamp,
            scenario=scenario,
            packet_id=i + 1,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )
        packets.append(packet)

    return {
        "session_id": hashlib.md5(f"{scenario}_{time.time()}".encode()).hexdigest()[:12],
        "scenario": scenario,
        "scenario_description": profile["description"],
        "total_packets": len(packets),
        "anomaly_count": sum(1 for p in packets if p["is_anomaly"]),
        "duration_minutes": duration_minutes,
        "start_time": start_time.isoformat(),
        "end_time": (start_time + timedelta(minutes=duration_minutes)).isoformat(),
        "packets": packets,
    }


def generate_dashboard_stats(session_data=None):
    """Generate dashboard statistics from a session or create fresh ones."""
    if session_data:
        packets = session_data["packets"]
        total = len(packets)
        anomalies = sum(1 for p in packets if p["is_anomaly"])

        protocol_dist = {}
        for p in packets:
            proto = p["protocol"]
            protocol_dist[proto] = protocol_dist.get(proto, 0) + 1

        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for p in packets:
            if p["is_anomaly"] and p["anomaly_severity"]:
                severity_dist[p["anomaly_severity"]] += 1

        weak_crypto_count = sum(1 for p in packets if not p["crypto_secure"])
    else:
        total = random.randint(800, 2500)
        anomalies = random.randint(15, 80)
        protocol_dist = {
            "ESP": int(total * 0.68),
            "AH": int(total * 0.10),
            "IKE": int(total * 0.17),
            "IKEv2": int(total * 0.05),
        }
        severity_dist = {
            "critical": random.randint(2, 8),
            "high": random.randint(5, 15),
            "medium": random.randint(8, 20),
            "low": random.randint(10, 25),
        }
        weak_crypto_count = random.randint(10, 50)

    # Security score calculation
    anomaly_penalty = min(40, (anomalies / max(total, 1)) * 500)
    crypto_penalty = min(30, (weak_crypto_count / max(total, 1)) * 300)
    security_score = max(0, min(100, int(100 - anomaly_penalty - crypto_penalty)))

    return {
        "total_packets_analyzed": total,
        "threats_detected": anomalies,
        "vulnerabilities_found": weak_crypto_count + severity_dist["critical"] + severity_dist["high"],
        "security_score": security_score,
        "security_grade": _score_to_grade(security_score),
        "threat_level": _score_to_threat_level(security_score),
        "protocol_distribution": protocol_dist,
        "severity_distribution": severity_dist,
        "top_anomaly_types": _get_top_anomalies(session_data) if session_data else [
            {"type": "replay_attack", "count": random.randint(2, 8)},
            {"type": "downgrade_attempt", "count": random.randint(3, 10)},
            {"type": "flood_attack", "count": random.randint(1, 5)},
            {"type": "spi_spoofing", "count": random.randint(2, 6)},
            {"type": "sequence_anomaly", "count": random.randint(4, 12)},
        ],
        "active_tunnels": random.randint(3, 12),
        "uptime_hours": round(random.uniform(24, 720), 1),
    }


def _score_to_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def _score_to_threat_level(score):
    if score >= 80: return "low"
    if score >= 60: return "moderate"
    if score >= 40: return "high"
    return "critical"


def _get_top_anomalies(session_data):
    if not session_data:
        return []
    counts = {}
    for p in session_data["packets"]:
        if p["is_anomaly"] and p["anomaly_type"]:
            counts[p["anomaly_type"]] = counts.get(p["anomaly_type"], 0) + 1
    return sorted(
        [{"type": k, "count": v} for k, v in counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]


def get_all_scenarios():
    """Return all available scenario profiles."""
    return {
        name: {
            "description": profile["description"],
            "anomaly_rate": profile["anomaly_rate"],
            "weak_crypto_rate": profile["weak_crypto_rate"],
        }
        for name, profile in SCENARIO_PROFILES.items()
    }
