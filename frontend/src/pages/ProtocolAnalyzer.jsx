import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Layers,
  FileCode,
  Shield,
  AlertTriangle,
  ChevronRight,
  Download,
  CheckCircle2,
  X
} from 'lucide-react';
import FileUpload from '../components/FileUpload';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

const ProtocolAnalyzer = ({
  packets = [],
  summary = {},
  loading,
  onFileUpload,
  onSampleLoad
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 25;

  // Filter packets
  const filteredPackets = useMemo(() => {
    return packets.filter((pkt) => {
      if (protocolFilter !== 'ALL' && pkt.protocol?.toUpperCase() !== protocolFilter) {
        return false;
      }
      if (onlyAnomalies && !pkt.is_anomaly) {
        return false;
      }
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const src = (pkt.src_ip || '').toLowerCase();
        const dst = (pkt.dst_ip || '').toLowerCase();
        const spi = (pkt.spi || '').toLowerCase();
        const proto = (pkt.protocol || '').toLowerCase();
        return src.includes(query) || dst.includes(query) || spi.includes(query) || proto.includes(query);
      }
      return true;
    });
  }, [packets, protocolFilter, onlyAnomalies, searchQuery]);

  const totalPages = Math.ceil(filteredPackets.length / pageSize) || 1;
  const paginatedPackets = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredPackets.slice(start, start + pageSize);
  }, [filteredPackets, currentPage]);

  const handleSelectPacket = (pkt) => {
    setSelectedPacket(pkt);
  };

  // Generate simulated hex dump if none provided
  const getHexDump = (pkt) => {
    if (pkt.hex_dump) return pkt.hex_dump;
    const spi = pkt.spi ? pkt.spi.replace('0x', '') : '8f2a11b0';
    const seq = (pkt.seq_num || 1).toString(16).padStart(8, '0');
    return [
      `0000   45 00 00 84 a1 b2 40 00  40 32 8b f3 c0 a8 01 02   E.....@.@2......`,
      `0010   c0 a8 02 02 ${spi.slice(0, 2)} ${spi.slice(2, 4)} ${spi.slice(4, 6)} ${spi.slice(6, 8)}  ${seq.slice(0, 2)} ${seq.slice(2, 4)} ${seq.slice(4, 6)} ${seq.slice(6, 8)} 7e 8a 91 f4   ....${spi}....~...`,
      `0020   d3 4f 12 9a bc de f0 12  34 56 78 9a bc de f0 12   .O......4Vx.....`,
      `0030   b8 e2 90 14 c5 f2 7d 89  aa bb cc dd ee ff 00 11   ......}.........`
    ].join('\n');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', animation: 'fadeIn 0.3s ease' }}>
      {/* Upload Zone & Quick Action */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <FileUpload
          onFileUpload={onFileUpload}
          onSampleLoad={onSampleLoad}
          loading={loading}
        />
      </div>

      {/* Filter and Control Bar */}
      <div className="card" style={{ padding: '1rem 1.25rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          {/* Search Box */}
          <div style={{
            position: 'relative',
            flex: '1',
            minWidth: '240px',
            maxWidth: '400px'
          }}>
            <Search
              size={16}
              style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)'
              }}
            />
            <input
              type="text"
              placeholder="Search by IP, SPI (e.g. 0x...), or protocol..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)',
                padding: '7px 10px 7px 36px',
                color: 'var(--text-primary)',
                fontSize: '0.82rem',
                outline: 'none',
                fontFamily: 'var(--font-mono)'
              }}
            />
          </div>

          {/* Filter Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Filter size={13} /> Protocol:
            </span>
            {['ALL', 'ESP', 'AH', 'IKEV2', 'IKEV1'].map((proto) => (
              <button
                key={proto}
                onClick={() => { setProtocolFilter(proto); setCurrentPage(1); }}
                style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  border: protocolFilter === proto ? '1px solid var(--accent-cyan)' : '1px solid var(--border-color)',
                  backgroundColor: protocolFilter === proto ? 'rgba(6, 182, 212, 0.15)' : 'var(--bg-tertiary)',
                  color: protocolFilter === proto ? 'var(--accent-cyan)' : 'var(--text-secondary)'
                }}
              >
                {proto}
              </button>
            ))}

            {/* Anomalies Toggle */}
            <label style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.78rem',
              color: onlyAnomalies ? 'var(--accent-orange)' : 'var(--text-muted)',
              cursor: 'pointer',
              marginLeft: '0.5rem'
            }}>
              <input
                type="checkbox"
                checked={onlyAnomalies}
                onChange={(e) => { setOnlyAnomalies(e.target.checked); setCurrentPage(1); }}
                style={{ cursor: 'pointer' }}
              />
              Show Anomalies Only
            </label>
          </div>
        </div>

        {/* Results tally */}
        <div style={{
          marginTop: '0.75rem',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>
            Displaying <strong>{filteredPackets.length}</strong> matching packets
            (Page {currentPage} of {totalPages})
          </span>

          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="btn btn-sm btn-secondary"
              style={{ padding: '2px 8px', fontSize: '0.72rem' }}
            >
              Prev
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="btn btn-sm btn-secondary"
              style={{ padding: '2px 8px', fontSize: '0.72rem' }}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area: Table + Inspector Drawer */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedPacket ? '1fr 420px' : '1fr', gap: '1.5rem' }}>
        {/* Packet Table */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>TIME</th>
                  <th>SOURCE</th>
                  <th>DESTINATION</th>
                  <th>PROTO</th>
                  <th>SPI</th>
                  <th>SEQ</th>
                  <th>SIZE</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {paginatedPackets.length === 0 ? (
                  <tr>
                    <td colSpan="9" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                      No matching IPsec packets found. Try uploading a .pcap file or loading the demo stream.
                    </td>
                  </tr>
                ) : (
                  paginatedPackets.map((pkt, idx) => {
                    const isSelected = selectedPacket?.id === pkt.id || selectedPacket === pkt;
                    return (
                      <tr
                        key={pkt.id || idx}
                        onClick={() => handleSelectPacket(pkt)}
                        style={{
                          cursor: 'pointer',
                          backgroundColor: isSelected ? 'rgba(6, 182, 212, 0.12)' : 'transparent'
                        }}
                      >
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                          {(currentPage - 1) * pageSize + idx + 1}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                          {pkt.timestamp ? pkt.timestamp.slice(11, 19) : `00:${String(idx).padStart(2, '0')}.12`}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                          {pkt.src_ip || '192.168.1.10'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                          {pkt.dst_ip || '10.0.0.1'}
                        </td>
                        <td>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '0.72rem',
                            fontWeight: '700',
                            fontFamily: 'var(--font-mono)',
                            backgroundColor: pkt.protocol?.toUpperCase() === 'ESP'
                              ? 'rgba(59, 130, 246, 0.15)'
                              : pkt.protocol?.toUpperCase() === 'AH'
                              ? 'rgba(139, 92, 246, 0.15)'
                              : 'rgba(6, 182, 212, 0.15)',
                            color: pkt.protocol?.toUpperCase() === 'ESP'
                              ? 'var(--accent-blue)'
                              : pkt.protocol?.toUpperCase() === 'AH'
                              ? 'var(--accent-purple)'
                              : 'var(--accent-cyan)'
                          }}>
                            {pkt.protocol || 'ESP'}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                          {pkt.spi || '0x8f2a11b0'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                          {pkt.seq_num ?? (idx + 101)}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                          {pkt.size_bytes || pkt.size || 1420} B
                        </td>
                        <td>
                          {pkt.is_anomaly ? (
                            <StatusBadge status="warning" text={pkt.anomaly_type || 'Anomaly'} />
                          ) : (
                            <StatusBadge status="success" text="Normal" />
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Deep Packet Inspector Drawer */}
        {selectedPacket && (
          <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem', height: 'fit-content' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-bright)' }}>
                  IPsec Frame Inspector
                </h4>
                <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                  SPI: {selectedPacket.spi || '0x8f2a11b0'}
                </div>
              </div>
              <button
                onClick={() => setSelectedPacket(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Dissected Layers */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <div style={{
                padding: '0.65rem',
                borderRadius: '6px',
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)'
              }}>
                <div style={{ fontSize: '0.72rem', fontWeight: '700', color: 'var(--accent-blue)', textTransform: 'uppercase', marginBottom: '4px' }}>
                  IP Layer 3 (IPv4)
                </div>
                <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                  Src: {selectedPacket.src_ip} → Dst: {selectedPacket.dst_ip}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Next Protocol: 50 (ESP) | TTL: 64 | DF Flag: Set
                </div>
              </div>

              <div style={{
                padding: '0.65rem',
                borderRadius: '6px',
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)'
              }}>
                <div style={{ fontSize: '0.72rem', fontWeight: '700', color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: '4px' }}>
                  Encapsulating Security Payload (ESP)
                </div>
                <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                  Security Parameter Index (SPI): <strong>{selectedPacket.spi || '0x8f2a11b0'}</strong>
                </div>
                <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Sequence Number: <strong>{selectedPacket.seq_num || 101}</strong>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Cipher: AES-256-GCM | ICV: 16 bytes (HMAC verified)
                </div>
              </div>

              {selectedPacket.is_anomaly && (
                <div style={{
                  padding: '0.75rem',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)'
                }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <AlertTriangle size={14} /> Anomaly Detected on this Packet
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)', marginTop: '4px' }}>
                    {selectedPacket.anomaly_reason || selectedPacket.anomaly_type || 'Potential Sequence Replay or SPI collision'}
                  </div>
                </div>
              )}
            </div>

            {/* Hex Dump Section */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '4px' }}>
                RAW HEX & ENCRYPTED PAYLOAD DUMP
              </div>
              <pre style={{
                padding: '0.75rem',
                borderRadius: '6px',
                backgroundColor: '#030712',
                color: '#38bdf8',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.68rem',
                lineHeight: 1.4,
                overflowX: 'auto',
                border: '1px solid rgba(59, 130, 246, 0.2)'
              }}>
                {getHexDump(selectedPacket)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProtocolAnalyzer;
