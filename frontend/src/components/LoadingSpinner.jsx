import React from 'react';

const LoadingSpinner = ({ text = 'Analyzing IPsec Packet Streams...' }) => {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '4rem 2rem',
      gap: '1.25rem',
      color: 'var(--text-secondary)'
    }}>
      <div style={{
        position: 'relative',
        width: '64px',
        height: '64px'
      }}>
        <div style={{
          position: 'absolute',
          inset: 0,
          border: '3px solid rgba(59, 130, 246, 0.15)',
          borderTopColor: 'var(--accent-cyan)',
          borderRightColor: 'var(--accent-blue)',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }} />
        <div style={{
          position: 'absolute',
          inset: '8px',
          border: '2px dashed rgba(139, 92, 246, 0.4)',
          borderRadius: '50%',
          animation: 'spin 2.5s linear infinite reverse'
        }} />
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '8px',
          height: '8px',
          backgroundColor: 'var(--accent-cyan)',
          borderRadius: '50%',
          boxShadow: '0 0 12px var(--accent-cyan)'
        }} />
      </div>
      <div style={{
        fontSize: '0.95rem',
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.05em',
        color: 'var(--accent-cyan)',
        textShadow: '0 0 10px rgba(6, 182, 212, 0.5)'
      }}>
        {text}
      </div>
    </div>
  );
};

export default LoadingSpinner;
