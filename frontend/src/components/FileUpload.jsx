import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle, CheckCircle2, RefreshCw } from 'lucide-react';

const FileUpload = ({ onFileUpload, onSampleLoad, loading }) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  };

  const handleFile = (file) => {
    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng') && !file.name.endsWith('.cap')) {
      alert('Please upload a valid .pcap, .pcapng, or .cap capture file.');
      return;
    }
    setSelectedFile(file);
    if (onFileUpload) {
      onFileUpload(file);
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      gap: '1rem',
      width: '100%'
    }}>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        style={{
          border: `2px dashed ${dragOver ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
          backgroundColor: dragOver ? 'rgba(6, 182, 212, 0.08)' : 'var(--bg-card)',
          borderRadius: 'var(--radius-lg)',
          padding: '2.5rem 1.5rem',
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'all var(--transition-fast)'
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files?.length) {
              handleFile(e.target.files[0]);
            }
          }}
        />

        <div style={{
          display: 'inline-flex',
          padding: '14px',
          borderRadius: '50%',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          color: 'var(--accent-cyan)',
          marginBottom: '1rem'
        }}>
          <UploadCloud size={32} />
        </div>

        <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--text-bright)' }}>
          {selectedFile ? selectedFile.name : 'Upload IPsec .pcap Packet Capture'}
        </div>

        <div style={{
          fontSize: '0.85rem',
          color: 'var(--text-secondary)',
          marginTop: '0.4rem',
          maxWidth: '420px',
          margin: '0.4rem auto 0'
        }}>
          {selectedFile
            ? `${(selectedFile.size / 1024).toFixed(1)} KB — Click or drag to replace`
            : 'Drag & drop real Wireshark captures here or click to browse. Scapy parser will extract IKEv1/v2, ESP & AH layers.'}
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '0.75rem',
          marginTop: '1.25rem'
        }}>
          <span style={{
            fontSize: '0.7rem',
            fontFamily: 'var(--font-mono)',
            padding: '3px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            color: 'var(--text-muted)'
          }}>
            SUPPORTED: .pcap, .pcapng, .cap
          </span>
          <span style={{
            fontSize: '0.7rem',
            fontFamily: 'var(--font-mono)',
            padding: '3px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            color: 'var(--text-muted)'
          }}>
            MAX: 100MB
          </span>
        </div>
      </div>

      {/* Or load realistic synthetic capture */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0.85rem 1.25rem',
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'var(--bg-tertiary)',
        border: '1px solid var(--border-color)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ color: 'var(--accent-purple)' }}>
            <File size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: '600', color: 'var(--text-primary)' }}>
              No live VPN capture handy?
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Load our pre-configured synthetic IPsec stream containing real replay attacks and weak crypto.
            </div>
          </div>
        </div>

        <button
          onClick={onSampleLoad}
          disabled={loading}
          className="btn btn-secondary btn-sm"
          style={{ whiteSpace: 'nowrap' }}
        >
          <RefreshCw size={13} className={loading ? 'spin' : ''} />
          <span>Load Synthetic Stream</span>
        </button>
      </div>
    </div>
  );
};

export default FileUpload;
