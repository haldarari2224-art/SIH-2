"""
API Routes
All REST API endpoints for the IPsec VPN Analyzer.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional

from core.packet_analyzer import PacketAnalyzer
from core.ml_engine import MLEngine
from core.security_scanner import SecurityScanner
from core.attack_simulator import AttackSimulator
from core.report_generator import ReportGenerator
from data.demo_generator import (
    generate_traffic_session,
    generate_dashboard_stats,
    get_all_scenarios,
)

router = APIRouter(prefix="/api")

# Initialize engines (singletons)
packet_analyzer = PacketAnalyzer()
ml_engine = MLEngine()
security_scanner = SecurityScanner()
attack_simulator = AttackSimulator()
report_generator = ReportGenerator()

# In-memory store for analysis sessions
sessions = {}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "IPsec VPN Analyzer", "ml_ready": ml_engine.is_trained}


@router.get("/scenarios")
async def get_scenarios():
    """Get available demo scenarios."""
    return get_all_scenarios()


@router.get("/demo")
async def load_demo(
    scenario: str = Query("corporate_vpn", description="Scenario profile"),
    num_packets: int = Query(500, ge=50, le=2000, description="Number of packets"),
):
    """Load a demo scenario with synthetic data."""
    if scenario not in get_all_scenarios():
        raise HTTPException(400, f"Unknown scenario: {scenario}")

    # Generate and analyze demo traffic
    analysis = packet_analyzer.analyze_demo(scenario=scenario, num_packets=num_packets)
    session_id = analysis["session_id"]

    # Run all analyses
    packets = analysis["packets"]
    ml_results = ml_engine.analyze_packets(packets)
    scan_results = security_scanner.scan(packets, session_id)
    sim_results = attack_simulator.simulate_all(packets, session_id)

    sessions[session_id] = {
        "analysis": analysis,
        "ml_results": ml_results,
        "scan_results": scan_results,
        "sim_results": sim_results,
    }

    return {
        "session_id": session_id,
        "scenario": scenario,
        "analysis_summary": {
            "total_packets": analysis["total_packets"],
            "anomaly_count": analysis.get("anomaly_count", 0),
            "protocols": analysis["protocol_summary"],
        },
        "ml_summary": {
            "total_anomalies": ml_results.get("total_anomalies", 0),
            "anomaly_rate": ml_results.get("anomaly_rate", 0),
        },
        "security_score": scan_results["security_score"],
        "security_grade": scan_results["security_grade"],
        "resilience_score": sim_results["resilience_score"],
    }


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload and analyze a .pcap file."""
    if not file.filename:
        raise HTTPException(400, "No file provided")

    # Accept common capture file extensions
    valid_exts = (".pcap", ".pcapng", ".cap")
    if not any(file.filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(400, f"Invalid file type. Accepted: {', '.join(valid_exts)}")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Analyze
    analysis = packet_analyzer.analyze_pcap(content, file.filename)
    session_id = analysis["session_id"]

    # Run ML + Security scan
    packets = analysis["packets"]
    ml_results = ml_engine.analyze_packets(packets)
    scan_results = security_scanner.scan(packets, session_id)
    sim_results = attack_simulator.simulate_all(packets, session_id)

    sessions[session_id] = {
        "analysis": analysis,
        "ml_results": ml_results,
        "scan_results": scan_results,
        "sim_results": sim_results,
    }

    return {
        "session_id": session_id,
        "filename": file.filename,
        "total_packets": analysis["total_packets"],
        "ipsec_packets": analysis["ipsec_packets"],
        "source": analysis["source"],
    }


@router.get("/analyze/{session_id}")
async def get_analysis(session_id: str):
    """Get full packet analysis results for a session."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session["analysis"]


@router.get("/analyze/{session_id}/packets")
async def get_packets(
    session_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=200),
    protocol: Optional[str] = None,
    anomaly_only: bool = False,
):
    """Get paginated packet list with optional filtering."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    packets = session["analysis"]["packets"]

    # Filter
    if protocol:
        packets = [p for p in packets if p.get("protocol") == protocol]
    if anomaly_only:
        packets = [p for p in packets if p.get("is_anomaly")]

    # Paginate
    total = len(packets)
    start = (page - 1) * per_page
    end = start + per_page
    page_packets = packets[start:end]

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "packets": page_packets,
    }


@router.get("/ml/{session_id}")
async def get_ml_results(session_id: str):
    """Get ML anomaly detection results."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session["ml_results"]


@router.get("/scan/{session_id}")
async def get_scan_results(session_id: str):
    """Get security scan results."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session["scan_results"]


@router.get("/simulate/{session_id}")
async def get_simulation_results(session_id: str):
    """Get attack simulation results."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session["sim_results"]


@router.post("/simulate/{session_id}")
async def run_single_simulation(
    session_id: str,
    attack_type: Optional[str] = Query(None, description="Attack vector ID to simulate")
):
    """Run an attack simulation on demand."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    packets = session["analysis"]["packets"]
    if attack_type:
        result = attack_simulator.simulate_single(attack_type, packets, session_id)
        # Format for frontend
        res = result.get("attack_result", result)
        return {
            "attack_type": attack_type,
            "vulnerable": res.get("vulnerable", False),
            "outcome": res.get("outcome") or res.get("details") or "Simulation completed.",
            "steps": res.get("simulation_steps") or [
                {"step": 1, "action": "Crafting IPsec attack probes", "status": "done"},
                {"step": 2, "action": "Injecting into simulated tunnel", "status": "done"},
                {"step": 3, "action": "Evaluating responder rejection metrics", "status": "done"}
            ],
            "remediation": res.get("remediation", "Enforce strict IPsec policy.")
        }
    return session["sim_results"]


@router.get("/simulate/{session_id}/attacks")
async def get_available_attacks(session_id: str):
    """Get available attack types."""
    return attack_simulator.get_available_attacks()


@router.get("/report/{session_id}")
async def get_report(session_id: str):
    """Generate a full security assessment report."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    report = report_generator.generate_full_report(
        session_id=session_id,
        analysis=session.get("analysis"),
        scan=session.get("scan_results"),
        ml_results=session.get("ml_results"),
        simulation=session.get("sim_results"),
    )

    return report


@router.get("/dashboard/stats")
async def get_dashboard_stats(session_id: Optional[str] = None):
    """Get dashboard overview statistics."""
    if session_id and session_id in sessions:
        session = sessions[session_id]
        analysis = session.get("analysis")
        stats = generate_dashboard_stats(analysis)

        # Overlay actual scan/ML data
        scan = session.get("scan_results", {})
        ml = session.get("ml_results", {})
        sim = session.get("sim_results", {})

        stats["security_score"] = scan.get("security_score", stats["security_score"])
        stats["security_grade"] = scan.get("security_grade", stats["security_grade"])
        stats["threats_detected"] = ml.get("total_anomalies", stats["threats_detected"])
        stats["vulnerabilities_found"] = len(scan.get("vulnerabilities", []))
        stats["resilience_score"] = sim.get("resilience_score", 0)
        stats["session_id"] = session_id
    else:
        stats = generate_dashboard_stats()
        stats["session_id"] = None

    return stats


@router.get("/sessions")
async def list_sessions():
    """List all analysis sessions."""
    return {
        "sessions": [
            {
                "session_id": sid,
                "filename": data["analysis"].get("filename", ""),
                "total_packets": data["analysis"].get("total_packets", 0),
                "security_score": data.get("scan_results", {}).get("security_score", 0),
                "timestamp": data["analysis"].get("timestamp", ""),
            }
            for sid, data in sessions.items()
        ]
    }
