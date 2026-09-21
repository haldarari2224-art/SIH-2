import React from 'react';

const StatusBadge = ({ status, text, size = 'sm' }) => {
  const normalized = (status || text || '').toString().toLowerCase();

  let badgeClass = 'badge-info';
  if (['critical', 'danger', 'fail', 'malicious', 'failed'].includes(normalized)) {
    badgeClass = 'badge-danger';
  } else if (['high', 'warning', 'suspicious', 'anomalous', 'anomaly'].includes(normalized)) {
    badgeClass = 'badge-warning';
  } else if (['medium'].includes(normalized)) {
    badgeClass = 'badge-orange';
  } else if (['low', 'info'].includes(normalized)) {
    badgeClass = 'badge-info';
  } else if (['pass', 'safe', 'normal', 'secure', 'success'].includes(normalized)) {
    badgeClass = 'badge-success';
  }

  const displayText = text || status;

  return (
    <span className={`badge ${badgeClass} ${size === 'lg' ? 'badge-lg' : ''}`}>
      <span className="badge-dot"></span>
      {displayText}
    </span>
  );
};

export default StatusBadge;
