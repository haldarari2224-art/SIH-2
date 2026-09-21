import React from 'react';

const SecurityGauge = ({ score = 85, size = 200, label = 'Security Posture Score' }) => {
  const radius = (size - 30) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use 240 degrees arc (from 150deg to 390deg)
  const arcLength = circumference * (240 / 360);
  const strokeDashoffset = arcLength - (Math.max(0, Math.min(100, score)) / 100) * arcLength;

  let color = 'var(--accent-green)';
  let grade = 'A';
  let ratingText = 'EXCELLENT';

  if (score >= 85) {
    color = '#10b981';
    grade = score >= 95 ? 'A+' : 'A';
    ratingText = 'SECURE';
  } else if (score >= 70) {
    color = '#06b6d4';
    grade = 'B';
    ratingText = 'GOOD';
  } else if (score >= 50) {
    color = '#f59e0b';
    grade = 'C';
    ratingText = 'MODERATE RISK';
  } else if (score >= 30) {
    color = '#f97316';
    grade = 'D';
    ratingText = 'HIGH RISK';
  } else {
    color = '#ef4444';
    grade = 'F';
    ratingText = 'CRITICAL RISK';
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative'
    }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(150deg)' }}>
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="12"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Value Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
              filter: `drop-shadow(0 0 10px ${color})`
            }}
          />
        </svg>

        {/* Center content */}
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          paddingBottom: '10px'
        }}>
          <span style={{
            fontSize: size > 160 ? '3rem' : '2.2rem',
            fontWeight: '900',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-bright)',
            lineHeight: 1,
            textShadow: `0 0 20px ${color}`
          }}>
            {Math.round(score)}
          </span>
          <span style={{
            fontSize: '0.75rem',
            letterSpacing: '0.1em',
            color: 'var(--text-muted)',
            marginTop: '4px'
          }}>
            / 100
          </span>
          <div style={{
            marginTop: '6px',
            padding: '2px 8px',
            borderRadius: '4px',
            backgroundColor: `${color}20`,
            border: `1px solid ${color}60`,
            color: color,
            fontSize: '0.75rem',
            fontWeight: '700',
            fontFamily: 'var(--font-mono)'
          }}>
            GRADE {grade}
          </div>
        </div>
      </div>

      <div style={{
        marginTop: '0.5rem',
        fontSize: '0.85rem',
        fontWeight: '600',
        letterSpacing: '0.05em',
        color: color,
        textTransform: 'uppercase'
      }}>
        {ratingText}
      </div>
      <div style={{
        fontSize: '0.8rem',
        color: 'var(--text-secondary)',
        marginTop: '2px'
      }}>
        {label}
      </div>
    </div>
  );
};

export default SecurityGauge;
