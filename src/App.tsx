import { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import './App.css';

interface SuricataAlert {
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  alert: {
    signature: string;
    category: string;
    severity: number;
  };
}

const SEVERITY_MAP: Record<number, { label: string; className: string }> = {
  1: { label: 'HIGH',   className: 'badge-high'   },
  2: { label: 'MEDIUM', className: 'badge-medium'  },
  3: { label: 'LOW',    className: 'badge-low'     },
};

function formatTime(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString('tr-TR', { hour12: false });
  } catch {
    return ts;
  }
}

export default function Dashboard() {
  const [alerts, setAlerts]       = useState<SuricataAlert[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const socket = io('http://localhost:5000');
    socket.on('connect',    () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('new_alert',  (data: SuricataAlert) =>
      setAlerts(prev => [data, ...prev].slice(0, 200))
    );
    return () => { socket.disconnect(); };
  }, []);

  const high   = alerts.filter(a => a.alert.severity === 1).length;
  const medium = alerts.filter(a => a.alert.severity === 2).length;
  const low    = alerts.filter(a => a.alert.severity === 3).length;

  return (
    <div className="db-root">
      {/* Header */}
      <header className="db-header">
        <div className="db-title">
          <span className="db-logo">⬡</span>
          <div>
            <h1>SURICATA IDS</h1>
            <p>Real-Time Threat Intelligence Dashboard</p>
          </div>
        </div>
        <div className={`db-status ${connected ? 'status-on' : 'status-off'}`}>
          <span className="status-dot" />
          {connected ? 'LIVE' : 'OFFLINE'}
        </div>
      </header>

      {/* Stat cards */}
      <div className="db-stats">
        <div className="stat-card">
          <span className="stat-value">{alerts.length}</span>
          <span className="stat-label">TOTAL ALERTS</span>
        </div>
        <div className="stat-card stat-high">
          <span className="stat-value">{high}</span>
          <span className="stat-label">HIGH</span>
        </div>
        <div className="stat-card stat-medium">
          <span className="stat-value">{medium}</span>
          <span className="stat-label">MEDIUM</span>
        </div>
        <div className="stat-card stat-low">
          <span className="stat-value">{low}</span>
          <span className="stat-label">LOW</span>
        </div>
      </div>

      {/* Alert table */}
      <div className="db-panel">
        <div className="panel-header">
          <span>ALERT FEED</span>
          {alerts.length > 0 && (
            <button className="clear-btn" onClick={() => setAlerts([])}>
              CLEAR
            </button>
          )}
        </div>

        {alerts.length === 0 ? (
          <div className="db-empty">
            <span className="empty-icon">◉</span>
            <p>Monitoring network traffic...</p>
            <p className="empty-sub">No threats detected</p>
          </div>
        ) : (
          <div className="alert-list">
            <div className="alert-row alert-row-head">
              <span>TIME</span>
              <span>SEV</span>
              <span>SIGNATURE</span>
              <span>SOURCE</span>
              <span>DESTINATION</span>
            </div>
            {alerts.map((a, i) => {
              const sev = SEVERITY_MAP[a.alert.severity] ?? { label: 'INFO', className: 'badge-low' };
              return (
                <div key={i} className={`alert-row alert-entry ${sev.className}-row`}>
                  <span className="col-time">{formatTime(a.timestamp)}</span>
                  <span><span className={`badge ${sev.className}`}>{sev.label}</span></span>
                  <span className="col-sig">{a.alert.signature}</span>
                  <span className="col-ip">{a.src_ip}</span>
                  <span className="col-ip">{a.dest_ip}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
