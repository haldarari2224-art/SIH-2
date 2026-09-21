import React, { useState } from 'react';
import { Shield, RefreshCw, Radio, CheckCircle2, AlertCircle, Database } from 'lucide-react';

const Header = ({
  activeSession,
  activeScenario,
  onScenarioChange,
  onReloadDemo,
  backendConnected,
  loading
}) => {
  return (
    <header style={{
      height: 'var(--header-height)',
      backgroundColor: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border-color)',
      padding: '0 1.5rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 40,
      backdropFilter: 'blur(12px)'
    }}>
      {/* Left: Brand & Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            background: 'var(--gradient-blue)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--glow-blue)'
          }}>
            <Shield size={18} color="#ffffff" />
          </div>
          <div>
            <div style={{
              fontSize: '1rem',
              fontWeight: '800',
              letterSpacing: '0.04em',
              background: 'linear-gradient(90deg, #ffffff, #06b6d4)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              lineHeight: 1.2
            }}>
              IPSEC SENTINEL
            </div>
            <div style={{
              fontSize: '0.68rem',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)'
            }}>
              SIH 2024 / PROTOCOL DEFENSE FRAMEWORK
            </div>
          </div>
        </div>

        {/* Backend Status Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 10px',
          borderRadius: '9999px',
          backgroundColor: backendConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${backendConnected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          fontSize: '0.72rem',
          fontFamily: 'var(--font-mono)'
        }}>
          <span style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            backgroundColor: backendConnected ? 'var(--accent-green)' : 'var(--accent-red)',
            boxShadow: `0 0 6px ${backendConnected ? 'var(--accent-green)' : 'var(--accent-red)'}`
          }} />
          <span style={{ color: backendConnected ? 'var(--accent-green)' : 'var(--accent-red)' }}>
            {backendConnected ? 'ENGINE ONLINE' : 'BACKEND OFFLINE'}
          </span>
        </div>
      </div>

      {/* Right: Scenario switch & Quick actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        {/* Scenario selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}>
            <Database size={13} /> Scenario:
          </span>
          <select
            value={activeScenario}
            onChange={(e) => onScenarioChange(e.target.value)}
            disabled={loading}
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '5px 10px',
              fontSize: '0.78rem',
              outline: 'none',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)'
            }}
          >
            <option value="corporate_vpn">Corporate VPN (Standard Enterprise)</option>
            <option value="compromised_tunnel">Compromised Tunnel (Attack Vector)</option>
            <option value="site_to_site">Site-to-Site (Legacy Weak Crypto)</option>
          </select>
        </div>

        {/* Reload Demo Data */}
        <button
          onClick={onReloadDemo}
          disabled={loading}
          className="btn btn-secondary btn-sm"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.75rem'
          }}
          title="Reload Demo Scenario"
        >
          <RefreshCw size={13} className={loading ? 'spin' : ''} />
          <span>Reset Demo</span>
        </button>

        {/* Active Session display */}
        {activeSession && (
          <div style={{
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid rgba(59, 130, 246, 0.25)',
            color: 'var(--accent-cyan)'
          }}>
            SESSION: #{activeSession.slice(0, 8)}
          </div>
        )}
      </div>
    </header>
  );
};

export default Header;
