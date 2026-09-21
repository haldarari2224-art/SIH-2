const API_BASE = '/api';

class ApiService {
  async request(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      if (err.message === 'Failed to fetch') {
        throw new Error('Cannot connect to backend. Make sure the server is running on port 8000.');
      }
      throw err;
    }
  }

  // Health
  health() { return this.request('/health'); }

  // Demo
  loadDemo(scenario = 'corporate_vpn', numPackets = 500) {
    return this.request(`/demo?scenario=${scenario}&num_packets=${numPackets}`);
  }

  getScenarios() { return this.request('/scenarios'); }

  // Upload
  async uploadPcap(file) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE}/upload`, { method: 'POST', body: formData });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }
    return await response.json();
  }

  // Analysis
  getAnalysis(sessionId) { return this.request(`/analyze/${sessionId}`); }
  getPackets(sessionId, page = 1, perPage = 50, protocol = null, anomalyOnly = false) {
    let url = `/analyze/${sessionId}/packets?page=${page}&per_page=${perPage}`;
    if (protocol) url += `&protocol=${protocol}`;
    if (anomalyOnly) url += `&anomaly_only=true`;
    return this.request(url);
  }

  // ML
  getMLResults(sessionId) { return this.request(`/ml/${sessionId}`); }

  // Security Scan
  getScanResults(sessionId) { return this.request(`/scan/${sessionId}`); }

  // Attack Simulation
  getSimulationResults(sessionId) { return this.request(`/simulate/${sessionId}`); }

  // Report
  getReport(sessionId) { return this.request(`/report/${sessionId}`); }

  // Dashboard
  getDashboardStats(sessionId = null) {
    const url = sessionId ? `/dashboard/stats?session_id=${sessionId}` : '/dashboard/stats';
    return this.request(url);
  }

  // Sessions
  listSessions() { return this.request('/sessions'); }
}

const api = new ApiService();
export default api;
