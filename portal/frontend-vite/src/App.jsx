import { useState, useEffect, useCallback } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';
import './App.css';

const API_BASE = '/api';

const SEVERITY_COLORS = {
  1: '#ef4444', // critical
  2: '#f97316', // high
  3: '#eab308', // medium
  4: '#22c55e', // low
};

const STATUS_COLORS = {
  open: '#ef4444',
  investigating: '#06b6d4',
  resolved: '#22c55e',
  blocked: '#f97316',
};

function formatTime(iso) {
  if (!iso) return '--';
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC';
}

function formatDateTime(iso) {
  if (!iso) return '--';
  return new Date(iso).toLocaleString('en-US', { 
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short'
  });
}

function SeverityBadge({ severity }) {
  return (
    <span className="px-2 py-0.5 text-xs font-medium rounded" style={{ backgroundColor: SEVERITY_COLORS[severity] + '20', color: SEVERITY_COLORS[severity] }}>
      {severity === 1 ? 'Critical' : severity === 2 ? 'High' : severity === 3 ? 'Medium' : 'Low'}
    </span>
  );
}

function StatusBadge({ status }) {
  return (
    <span className="px-2 py-0.5 text-xs font-medium rounded capitalize" style={{ backgroundColor: STATUS_COLORS[status] + '20', color: STATUS_COLORS[status] }}>
      {status}
    </span>
  );
}

function IOCBadge({ ip }) {
  const [ioc, setIoc] = useState(null);
  useEffect(() => {
    fetch(`${API_BASE}/ioc/${ip}`)
      .then(r => r.json())
      .then(setIoc)
      .catch(() => setIoc({ malicious: false }));
  }, [ip]);
  if (!ioc) return <span className="px-2 py-0.5 text-xs text-soc-textMuted">Checking...</span>;
  if (!ioc.malicious) return <span className="px-2 py-0.5 text-xs text-soc-low bg-soc-low/10 rounded">Clean</span>;
  return (
    <span className="px-2 py-0.5 text-xs font-medium rounded bg-soc-critical/10 text-soc-critical flex items-center gap-1">
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      Known Malicious
    </span>
  );
}

function ErrorBanner({ message, onDismiss }) {
  if (!message) return null;
  return (
    <div className="fixed top-4 right-4 z-50 bg-soc-critical/90 text-white px-4 py-3 rounded-lg shadow-lg flex items-center gap-3 max-w-md animate-slide-in">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="flex-shrink-0">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <span className="text-sm">{message}</span>
      <button onClick={onDismiss} className="ml-auto text-white/70 hover:text-white">✕</button>
    </div>
  );
}

function IncidentDetailModal({ incident, onClose }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState(incident?.status || 'open');
  const [note, setNote] = useState(incident?.analyst_note || '');

  useEffect(() => {
    if (!incident) return;
    fetch(`${API_BASE}/incidents/${incident.id}/timeline`)
      .then(r => r.json())
      .then(d => { setTimeline(d.events || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [incident]);

  const handleUpdate = async () => {
    try {
      await fetch(`${API_BASE}/incidents/${incident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, analyst_note: note }),
      });
      onClose();
    } catch (e) {
      alert('Failed to update incident');
    }
  };

  if (!incident) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-soc-panel border border-soc-border rounded-xl max-w-4xl w-full max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-soc-border">
          <h2 className="text-lg font-semibold">Incident #{incident.id} - {incident.src_ip}</h2>
          <button onClick={onClose} className="text-soc-textMuted hover:text-white">✕</button>
        </div>
        <div className="p-4 overflow-y-auto flex-1 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">Severity</p>
              <SeverityBadge severity={incident.severity} />
            </div>
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">Count</p>
              <p className="font-mono text-lg">{incident.count}</p>
            </div>
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">Status</p>
              <StatusBadge status={incident.status} />
            </div>
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">IOC</p>
              <IOCBadge ip={incident.src_ip} />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">First Seen</p>
              <p className="font-mono">{formatDateTime(incident.first_seen)}</p>
            </div>
            <div className="bg-soc-bg p-3 rounded-lg">
              <p className="text-xs text-soc-textMuted">Last Seen</p>
              <p className="font-mono">{formatDateTime(incident.last_seen)}</p>
            </div>
          </div>
          <div className="bg-soc-bg p-3 rounded-lg">
            <p className="text-xs text-soc-textMuted mb-2">Analyst Note</p>
            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              className="w-full bg-soc-panel border border-soc-border rounded p-2 text-sm font-mono text-soc-text"
              rows={3}
              placeholder="Add investigation notes..."
            />
          </div>
          <div className="flex gap-2">
            <select
              value={status}
              onChange={e => setStatus(e.target.value)}
              className="bg-soc-panel border border-soc-border rounded px-3 py-2 text-sm"
            >
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="blocked">Blocked</option>
            </select>
            <button onClick={handleUpdate} className="px-4 py-2 bg-soc-accent text-soc-bg font-medium rounded hover:bg-cyan-300">
              Update
            </button>
          </div>
          <div className="border-t border-soc-border pt-4">
            <h3 className="font-medium mb-3">Event Timeline (Last 50 Events)</h3>
            {loading ? (
              <div className="text-center text-soc-textMuted py-8">Loading timeline...</div>
            ) : timeline.length === 0 ? (
              <div className="text-center text-soc-textMuted py-8">No events found for this IP</div>
            ) : (
              <div className="max-h-96 overflow-y-auto scrollbar-thin">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-soc-textMuted border-b border-soc-border">
                      <th className="pb-2 font-mono w-32">Time</th>
                      <th className="pb-2">User</th>
                      <th className="pb-2">Port</th>
                      <th className="pb-2 font-mono">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {timeline.map((evt, i) => (
                      <tr key={i} className="border-b border-soc-border/50 hover:bg-soc-bg/50">
                        <td className="py-1 font-mono text-soc-textMuted">{formatTime(evt['@timestamp'])}</td>
                        <td className="py-1">{evt.user}</td>
                        <td className="py-1 font-mono">{evt.port}</td>
                        <td className="py-1 font-mono text-soc-textMuted truncate max-w-xs">{evt.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function OverviewPage({ stats, incidents, error, onRefresh }) {
  const severityData = Object.entries(stats.by_severity || {}).map(([severity, count]) => ({
    severity: parseInt(severity),
    count,
    label: severity === '1' ? 'Critical' : severity === '2' ? 'High' : severity === '3' ? 'Medium' : 'Low',
    color: SEVERITY_COLORS[parseInt(severity)],
  }));

  const statusData = Object.entries(stats.by_status || {}).map(([status, count]) => ({
    status,
    count,
    color: STATUS_COLORS[status] || '#6b7280',
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Overview</h1>
        <button onClick={onRefresh} className="px-4 py-2 bg-soc-accent/20 text-soc-accent rounded-lg hover:bg-soc-accent/30 text-sm font-medium flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
          </svg>
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-soc-textMuted">Open Incidents</p>
              <p className="text-3xl font-bold text-soc-critical mt-1">{stats.by_status?.open || 0}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-soc-critical/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
          </div>
        </div>
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-soc-textMuted">Critical (Sev 1)</p>
              <p className="text-3xl font-bold text-soc-critical mt-1">{stats.by_severity[1] || 0}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-soc-critical/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
            </div>
          </div>
        </div>
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-soc-textMuted">Events (Last Hour)</p>
              <p className="text-3xl font-bold text-soc-accent mt-1">
                {(stats.events_per_minute || []).reduce((a, b) => a + b.count, 0)}
              </p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-soc-accent/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="2">
                <path d="M18 8h1a4 4 0 010 8h-1"/><path d="M2 8h16v9a4 4 0 01-4 4H6a4 4 0 01-4-4V8z"/>
                <line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/><line x1="14" y1="1" x2="14" y2="4"/>
              </svg>
            </div>
          </div>
        </div>
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-soc-textMuted">Total Incidents</p>
              <p className="text-3xl font-bold text-soc-text mt-1">{stats.total_incidents || 0}</p>
            </div>
            <div className="w-12 h-12 rounded-xl bg-soc-accent/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
              </svg>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <h3 className="font-medium mb-4">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%" cy="50%" innerRadius={60} outerRadius={80}
                  paddingAngle={2} dataKey="count" nameKey="label"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip formatter={v => [v, 'incidents']} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <h3 className="font-medium mb-4">Status Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="status" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} width={80} />
                <Tooltip formatter={v => [v, 'incidents']} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {statusData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <h3 className="font-medium mb-4">Events per Minute (Last Hour)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats.events_per_minute || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="timestamp" tick={{ fill: '#9ca3af', fontSize: 10 }} axisLine={false} tickLine={false} tickCount={12} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip formatter={v => [v, 'events']} />
                <Line type="monotone" dataKey="count" stroke="#06b6d4" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
          <h3 className="font-medium mb-4">Top Attacker IPs</h3>
          <div className="space-y-3">
            {(stats.top_attackers || []).map((attacker, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-soc-bg rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 bg-soc-accent/20 text-soc-accent rounded-full flex items-center justify-center text-sm font-bold">{i + 1}</span>
                  <div>
                    <p className="font-mono text-sm">{attacker.ip}</p>
                    <p className="text-xs text-soc-textMuted">{attacker.count} events</p>
                  </div>
                </div>
                <IOCBadge ip={attacker.ip} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function IncidentsPage({ incidents, setIncidents, error, onRefresh }) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState(null);

  const filtered = incidents.filter(i => statusFilter === 'all' || i.status === statusFilter);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <h1 className="text-2xl font-bold">Incidents</h1>
        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="blocked">Blocked</option>
          </select>
          <button onClick={onRefresh} className="px-4 py-2 bg-soc-accent/20 text-soc-accent rounded-lg hover:bg-soc-accent/30 text-sm font-medium flex items-center gap-2">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
              <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <div className="bg-soc-panel border border-soc-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-soc-textMuted border-b border-soc-border">
                <th className="p-3 font-mono text-xs">ID</th>
                <th className="p-3 font-mono text-xs">Source IP</th>
                <th className="p-3 text-xs">Severity</th>
                <th className="p-3 text-xs">Count</th>
                <th className="p-3 text-xs">First Seen</th>
                <th className="p-3 text-xs">Last Seen</th>
                <th className="p-3 text-xs">Status</th>
                <th className="p-3 text-xs">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={8} className="p-8 text-center text-soc-textMuted">No incidents found</td></tr>
              ) : (
                filtered.map(inc => (
                  <tr key={inc.id} className="border-b border-soc-border/50 hover:bg-soc-bg/50 cursor-pointer" onClick={() => setSelectedIncident(inc)}>
                    <td className="p-3 font-mono text-sm">{inc.id}</td>
                    <td className="p-3 font-mono text-sm">{inc.src_ip}</td>
                    <td className="p-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="p-3 font-mono text-sm">{inc.count}</td>
                    <td className="p-3 text-sm text-soc-textMuted">{formatDateTime(inc.first_seen)}</td>
                    <td className="p-3 text-sm text-soc-textMuted">{formatDateTime(inc.last_seen)}</td>
                    <td className="p-3"><StatusBadge status={inc.status} /></td>
                    <td className="p-3">
                      <a 
                        href={`http://localhost:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:'src_ip:%22${inc.src_ip}%22'))`} 
                        target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="text-soc-accent hover:underline text-sm flex items-center gap-1"
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
                          <polyline points="15 3 21 3 21 9"/>
                          <line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                        OpenSearch
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedIncident && <IncidentDetailModal incident={selectedIncident} onClose={() => setSelectedIncident(null)} />}
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState('overview');
  const [stats, setStats] = useState({ by_severity: {}, by_status: {}, top_attackers: [], events_per_minute: [], total_incidents: 0 });
  const [incidents, setIncidents] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [statsRes, incRes] = await Promise.all([
        fetch(`${API_BASE}/stats`).then(r => r.json()),
        fetch(`${API_BASE}/incidents`).then(r => r.json()),
      ]);
      setStats(statsRes);
      setIncidents(incRes.incidents || []);
    } catch (e) {
      setError('Failed to connect to API. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="min-h-screen bg-soc-bg font-sans">
      <ErrorBanner message={error} onDismiss={() => setError(null)} />
      
      <nav className="bg-soc-panel border-b border-soc-border sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-soc-accent rounded-lg flex items-center justify-center">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <span className="font-bold text-lg">SIEM-Lab</span>
              <span className="text-xs text-soc-textMuted">Security Operations Center</span>
            </div>
            <div className="flex items-center gap-6">
              <button onClick={() => setPage('overview')} className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${page === 'overview' ? 'bg-soc-accent text-soc-bg' : 'text-soc-textMuted hover:text-white hover:bg-soc-bg'}`}>
                Overview
              </button>
              <button onClick={() => setPage('incidents')} className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${page === 'incidents' ? 'bg-soc-accent text-soc-bg' : 'text-soc-textMuted hover:text-white hover:bg-soc-bg'}`}>
                Incidents
              </button>
              <div className="flex items-center gap-2 text-sm text-soc-textMuted">
                <span className="relative">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  <span className="ml-2">Live</span>
                </span>
                <span className="font-mono text-soc-accent" id="nav-time">--:--:-- UTC</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-8 h-8 border-4 border-soc-accent border-t-transparent rounded-full animate-spin"></div>
          </div>
        ) : page === 'overview' ? (
          <OverviewPage stats={stats} incidents={incidents} error={error} onRefresh={fetchData} />
        ) : (
          <IncidentsPage incidents={incidents} setIncidents={setIncidents} error={error} onRefresh={fetchData} />
        )}
      </main>
    </div>
  );
}