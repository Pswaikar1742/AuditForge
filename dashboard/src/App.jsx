import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Flame, Lock, Terminal,
  RefreshCw, Database, Layers, Search, ExternalLink, ChevronRight,
  ChevronDown, Cpu, FileCode, Radio, Zap
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [baselines, setBaselines] = useState([]);
  const [fixtures, setFixtures] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [customPath, setCustomPath] = useState('');
  const [apiOnline, setApiOnline] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  useEffect(() => {
    checkHealth();
    fetchStats();
    fetchScans();
    fetchBaselines();
    fetchFixtures();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      setApiOnline(res.ok);
    } catch {
      setApiOnline(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      if (res.ok) setStats(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scans`);
      if (res.ok) {
        const data = await res.json();
        setScans(data);
        if (data.length > 0 && !selectedScan) {
          fetchScanDetails(data[0].id);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchScanDetails = async (scanId) => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchBaselines = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/baselines`);
      if (res.ok) setBaselines(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchFixtures = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/fixtures`);
      if (res.ok) setFixtures(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const runScan = async (path, name) => {
    setLoading(true);
    setStatusMsg(`Running security audit on ${name || path}...`);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          server_path: path,
          server_name: name,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        setSelectedScan(result);
        setStatusMsg(`Scan completed: ${result.findings?.length || 0} finding(s) detected.`);
        fetchStats();
        fetchScans();
        fetchBaselines();
      } else {
        const err = await res.json();
        setStatusMsg(`Scan failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Connection error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const approveBaseline = async (serverName) => {
    try {
      const res = await fetch(`${API_BASE}/api/baselines/${serverName}/approve`, {
        method: 'POST',
      });
      if (res.ok) {
        setStatusMsg(`Baseline for '${serverName}' approved.`);
        fetchBaselines();
        fetchScans();
        if (selectedScan) fetchScanDetails(selectedScan.id);
      }
    } catch (e) {
      setStatusMsg(`Approval failed: ${e.message}`);
    }
  };

  // Helper styles for trust state badge
  const renderTrustBadge = (state) => {
    switch (state) {
      case 'APPROVED':
      case 'VERIFIED':
        return <span className="badge badge-approved"><CheckCircle size={13} /> VERIFIED</span>;
      case 'REVOKED':
      case 'ROGUE':
        return <span className="badge badge-revoked"><AlertTriangle size={13} /> ROGUE</span>;
      case 'TRUST_GAP':
        return <span className="badge badge-review" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#F87171', border: '1px solid rgba(239, 68, 68, 0.4)' }}><AlertTriangle size={13} /> TRUST GAP</span>;
      case 'REVIEW':
      case 'SUSPICIOUS':
      default:
        return <span className="badge badge-review"><ClockIcon size={13} /> IN REVIEW</span>;
    }
  };

  const ClockIcon = ({ size }) => <span style={{ display: 'inline-block', width: size, height: size, borderRadius: '50%', border: '2px solid currentColor' }} />;

  // Filter findings
  const findingsList = (selectedScan?.findings || []).filter(f => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* ── Top Header ───────────────────────────────────────────── */}
      <header style={{
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(11, 15, 25, 0.85)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        padding: '0.85rem 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #06B6D4, #4F46E5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.3)',
          }}>
            <Shield size={24} color="#FFFFFF" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: '800', letterSpacing: '-0.02em', background: 'linear-gradient(to right, #F8FAFC, #94A3B8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                AUDIT FORGE
              </h1>
              <span style={{ fontSize: '0.65rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(6, 182, 212, 0.15)', color: '#06B6D4', fontWeight: '700', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
                PS02
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              MCP Server Security Auditor & Contract-to-Behavior Trust Engine
            </p>
          </div>
        </div>

        {/* Backend health status badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: apiOnline ? '#10B981' : '#EF4444',
              boxShadow: apiOnline ? '0 0 10px #10B981' : '0 0 10px #EF4444',
            }} />
            <span style={{ color: apiOnline ? '#34D399' : '#F87171', fontWeight: '600' }}>
              {apiOnline ? 'FastAPI Connected (8000)' : 'API Disconnected'}
            </span>
          </div>

          <button
            onClick={() => { fetchStats(); fetchScans(); fetchBaselines(); }}
            className="btn btn-secondary"
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </header>

      {/* ── Subnav Tabs ─────────────────────────────────────────── */}
      <div style={{
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(7, 9, 14, 0.6)',
        padding: '0.5rem 2rem',
        display: 'flex',
        gap: '0.75rem',
      }}>
        {[
          { id: 'scanner', label: 'Security Auditor', icon: Shield },
          { id: 'findings', label: `Evidence Explorer (${selectedScan?.findings?.length || 0})`, icon: Layers },
          { id: 'baselines', label: `Baseline Registry (${baselines.length})`, icon: Database },
          { id: 'architecture', label: 'USP & System Specs', icon: Cpu },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontWeight: '600',
                cursor: 'pointer',
                background: isActive ? 'rgba(6, 182, 212, 0.12)' : 'transparent',
                color: isActive ? '#06B6D4' : 'var(--text-secondary)',
                border: isActive ? '1px solid rgba(6, 182, 212, 0.3)' : '1px solid transparent',
                transition: 'all 0.15s ease',
              }}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Status banner */}
      {statusMsg && (
        <div style={{
          background: 'rgba(6, 182, 212, 0.08)',
          borderBottom: '1px solid rgba(6, 182, 212, 0.2)',
          padding: '0.5rem 2rem',
          fontSize: '0.85rem',
          color: '#38BDF8',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <Zap size={14} /> {statusMsg}
        </div>
      )}

      {/* ── Main Content Area ───────────────────────────────────── */}
      <main style={{ flex: 1, padding: '2rem', maxWidth: '1600px', margin: '0 auto', width: '100%' }}>

        {/* ── Tab: Scanner & Fixtures ───────────────────────────── */}
        {activeTab === 'scanner' && (
          <div>
            {/* Top Metrics Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.25rem', marginBottom: '2rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Total Scans</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#F8FAFC' }}>
                  {stats?.total_scans || scans.length}
                </div>
                <span style={{ fontSize: '0.75rem', color: '#10B981' }}>Live SQLite persistence</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Critical / High Findings</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#F43F5E' }}>
                  {(stats?.findings_by_severity?.CRITICAL || 0) + (stats?.findings_by_severity?.HIGH || 0)}
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Backed by evidence capsules</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Pinned Baselines</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#38BDF8' }}>
                  {baselines.length}
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SHA-256 fingerprint anchors</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Current Target State</span>
                <div style={{ marginTop: '0.5rem' }}>
                  {selectedScan ? renderTrustBadge(selectedScan.trust_state) : <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No scan selected</span>}
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.4rem' }}>
                  {selectedScan?.server_name || 'Select target'}
                </span>
              </div>
            </div>

            {/* Live Interactive Scanner Layout */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '2rem' }}>
              {/* Left Column: Synthetic Test Fixtures */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Flame size={18} color="#F97316" />
                    Competition Synthetic Fixtures (Evaluation Benchmark)
                  </h2>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                  As mandated by PS02 rules, test exclusively against team-owned synthetic fixtures. Each fixture benchmarks a distinct defense capability:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {fixtures.map((fix) => (
                    <div
                      key={fix.id}
                      className="glass-panel"
                      style={{
                        padding: '1.25rem',
                        borderLeft: fix.id === 'fixture_a_clean_reader' ? '4px solid #10B981' : fix.id === 'fixture_e_lying_annotations' ? '4px solid #6366F1' : '4px solid #F97316',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div style={{ flex: 1, paddingRight: '1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: '700', fontSize: '0.95rem' }}>{fix.name}</span>
                          <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>
                            {fix.role}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                          <strong style={{ color: '#E2E8F0' }}>Target:</strong> {fix.expected}
                        </div>
                        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                          {fix.tags.map(t => (
                            <span key={t} style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(6, 182, 212, 0.08)', color: '#38BDF8' }}>
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>

                      <button
                        onClick={() => runScan(fix.path, fix.id)}
                        disabled={loading}
                        className="btn btn-primary"
                        style={{ minWidth: '130px' }}
                      >
                        {loading ? <RefreshCw size={14} className="spin" /> : <Terminal size={14} />}
                        Audit Server
                      </button>
                    </div>
                  ))}
                </div>

                {/* Custom Path Scanner Box */}
                <div className="glass-panel" style={{ marginTop: '2rem', padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: '700', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Terminal size={16} color="#06B6D4" />
                    Audit Custom Local MCP Target Directory
                  </h3>
                  <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <input
                      type="text"
                      placeholder="e.g. C:\path\to\mcp-server"
                      value={customPath}
                      onChange={(e) => setCustomPath(e.target.value)}
                      style={{
                        flex: 1,
                        background: '#05070B',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        padding: '0.6rem 0.9rem',
                        color: '#F8FAFC',
                        fontSize: '0.85rem',
                        fontFamily: 'var(--font-mono)',
                      }}
                    />
                    <button
                      onClick={() => runScan(customPath, 'custom_target')}
                      disabled={loading || !customPath}
                      className="btn btn-secondary"
                    >
                      Scan Custom
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: Active Scan Overview */}
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: '700', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Shield size={18} color="#06B6D4" />
                  Active Scan Summary
                </h2>

                {selectedScan ? (
                  <div className="glass-panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.1rem', fontWeight: '700' }}>{selectedScan.server_name}</h3>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Scan ID: {selectedScan.id}</span>
                      </div>
                      {renderTrustBadge(selectedScan.trust_state)}
                    </div>

                    <div style={{ borderTop: '1px solid var(--border-subtle)', borderBottom: '1px solid var(--border-subtle)', padding: '1rem 0', margin: '1rem 0', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Catalog Hash:</span>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#38BDF8', marginTop: '0.2rem' }}>
                          {selectedScan.catalog_hash ? `${selectedScan.catalog_hash.slice(0, 16)}...` : 'N/A'}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Status:</span>
                        <div style={{ fontWeight: '600', color: selectedScan.status === 'COMPLETED' ? '#10B981' : '#F43F5E', marginTop: '0.2rem' }}>
                          {selectedScan.status}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Baseline Match:</span>
                        <div style={{ fontWeight: '600', color: selectedScan.baseline_match ? '#10B981' : '#F59E0B', marginTop: '0.2rem' }}>
                          {selectedScan.baseline_match ? '✓ Matches Baseline' : '⚠️ Drift / New Target'}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Total Findings:</span>
                        <div style={{ fontWeight: '700', color: '#F8FAFC', marginTop: '0.2rem' }}>
                          {selectedScan.findings?.length || 0}
                        </div>
                      </div>
                    </div>

                    {/* Quick Findings Breakdown */}
                    <div style={{ marginBottom: '1.25rem' }}>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: '600' }}>Vulnerability Breakdown:</span>
                      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                          const count = (selectedScan.findings || []).filter(f => f.severity === sev).length;
                          return (
                            <div key={sev} style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', textAlign: 'center', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-subtle)' }}>
                              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{sev}</div>
                              <div style={{ fontSize: '1.1rem', fontWeight: '800', color: count > 0 ? (sev === 'CRITICAL' ? '#F43F5E' : sev === 'HIGH' ? '#F97316' : '#FBBF24') : '#64748B' }}>
                                {count}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <button
                        onClick={() => setActiveTab('findings')}
                        className="btn btn-secondary"
                        style={{ flex: 1 }}
                      >
                        <Layers size={14} /> View Evidence
                      </button>

                      {selectedScan.trust_state !== 'APPROVED' && (
                        <button
                          onClick={() => approveBaseline(selectedScan.server_name)}
                          className="btn btn-success"
                        >
                          <CheckCircle size={14} /> Approve Baseline
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <Shield size={36} style={{ margin: '0 auto 1rem', opacity: 0.4 }} />
                    <p>Select a synthetic fixture on the left to trigger a live scan.</p>
                  </div>
                )}

                {/* Recent Scans History Table */}
                <div className="glass-panel" style={{ marginTop: '1.5rem', padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.9rem', fontWeight: '700', marginBottom: '0.75rem' }}>Recent Scans in Database</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '220px', overflowY: 'auto' }}>
                    {scans.map(s => (
                      <div
                        key={s.id}
                        onClick={() => fetchScanDetails(s.id)}
                        style={{
                          padding: '0.6rem 0.8rem',
                          borderRadius: '6px',
                          background: selectedScan?.id === s.id ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255,255,255,0.02)',
                          border: selectedScan?.id === s.id ? '1px solid rgba(6, 182, 212, 0.3)' : '1px solid transparent',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          cursor: 'pointer',
                        }}
                      >
                        <div>
                          <div style={{ fontSize: '0.85rem', fontWeight: '600' }}>{s.server_name}</div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{s.id.slice(0, 12)}...</div>
                        </div>
                        {renderTrustBadge(s.trust_state)}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Tab: Evidence Explorer ────────────────────────────── */}
        {activeTab === 'findings' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>
                  Evidence-Linked Findings for {selectedScan?.server_name || 'Target'}
                </h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Every finding is grounded in an immutable Evidence Capsule with source code line numbers, AST nodes, or runtime events. Zero hallucinations.
                </p>
              </div>

              {/* Filter pills */}
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    style={{
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontWeight: '700',
                      cursor: 'pointer',
                      background: severityFilter === sev ? '#06B6D4' : 'rgba(255,255,255,0.05)',
                      color: severityFilter === sev ? '#000000' : 'var(--text-secondary)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {findingsList.length === 0 ? (
              <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                <CheckCircle size={36} color="#10B981" style={{ margin: '0 auto 1rem' }} />
                <h3 style={{ color: '#F8FAFC', fontWeight: '700' }}>No findings detected for this filter</h3>
                <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>Target exhibits clean behavior or matches approved baseline specifications.</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {findingsList.map((f, idx) => {
                  const isExpanded = expandedFinding === f.id;
                  let parsedEvidence = [];
                  try {
                    parsedEvidence = typeof f.evidence === 'string' ? JSON.parse(f.evidence) : f.evidence;
                  } catch {
                    parsedEvidence = [];
                  }

                  return (
                    <div key={f.id || idx} className="glass-panel" style={{ padding: '1.25rem' }}>
                      <div
                        onClick={() => setExpandedFinding(isExpanded ? null : f.id)}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <span className={`badge sev-${f.severity.toLowerCase()}`}>
                            {f.severity}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#06B6D4', fontWeight: '700' }}>
                            {f.rule_id}
                          </span>
                          <span style={{ fontWeight: '700', fontSize: '0.95rem' }}>
                            {f.title}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            Analyzer: <strong style={{ color: '#E2E8F0' }}>{f.analyzer}</strong>
                          </span>
                          {isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                        </div>
                      </div>

                      {/* Description */}
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.75rem' }}>
                        {f.description}
                      </p>

                      {/* Expanded Evidence Capsule */}
                      {isExpanded && (
                        <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
                          <h4 style={{ fontSize: '0.85rem', fontWeight: '700', color: '#06B6D4', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <FileCode size={15} />
                            Evidence Capsule Trace
                          </h4>

                          {parsedEvidence && parsedEvidence.length > 0 ? (
                            parsedEvidence.map((ev, eIdx) => (
                              <div key={eIdx} className="code-box" style={{ marginBottom: '0.75rem' }}>
                                <div style={{ color: '#38BDF8', marginBottom: '0.35rem', display: 'flex', justifyContent: 'space-between' }}>
                                  <span>Type: {ev.evidence_type}</span>
                                  {ev.source_file && <span>{ev.source_file}:{ev.line_number}</span>}
                                </div>
                                {ev.line_content && (
                                  <div style={{ background: '#0F172A', padding: '0.5rem', borderRadius: '4px', borderLeft: '3px solid #F43F5E', color: '#F1F5F9' }}>
                                    {ev.line_content}
                                  </div>
                                )}
                                {ev.snippet && (
                                  <pre style={{ margin: '0.5rem 0 0 0', whiteSpace: 'pre-wrap', color: '#CBD5E1' }}>
                                    {ev.snippet}
                                  </pre>
                                )}
                                {ev.description && (
                                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.35rem' }}>
                                    Details: {ev.description}
                                  </div>
                                )}
                              </div>
                            ))
                          ) : (
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No additional raw snippet captured.</div>
                          )}

                          {/* Remediation */}
                          {f.remediation && (
                            <div style={{ marginTop: '0.75rem', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                              <span style={{ fontSize: '0.8rem', fontWeight: '700', color: '#34D399' }}>💡 Remediation Advice:</span>
                              <p style={{ fontSize: '0.8rem', color: '#E2E8F0', marginTop: '0.2rem' }}>{f.remediation}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Baseline Registry ────────────────────────────── */}
        {activeTab === 'baselines' && (
          <div>
            <div style={{ marginBottom: '1.5rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>Cryptographic Catalog Baseline Registry</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Pin-and-diff engine monitors SHA-256 tool catalog hashes. Any unapproved modifications, parameter insertions, or stealth tool registrations automatically trigger a REVOKED rug-pull state.
              </p>
            </div>

            <div className="glass-panel" style={{ padding: '1rem', overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Server Target</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Catalog SHA-256 Hash</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Trust Lifecycle</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Approved By</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {baselines.map(b => (
                    <tr key={b.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '1rem', fontWeight: '700' }}>{b.server_name}</td>
                      <td style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#38BDF8' }}>
                        {b.catalog_hash}
                      </td>
                      <td style={{ padding: '1rem' }}>{renderTrustBadge(b.trust_state)}</td>
                      <td style={{ padding: '1rem', color: 'var(--text-muted)' }}>{b.approved_by || '—'}</td>
                      <td style={{ padding: '1rem' }}>
                        {b.trust_state !== 'APPROVED' ? (
                          <button
                            onClick={() => approveBaseline(b.server_name)}
                            className="btn btn-success"
                            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
                          >
                            Approve
                          </button>
                        ) : (
                          <span style={{ color: '#10B981', fontSize: '0.75rem', fontWeight: '600' }}>✓ Verified</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Architecture & USPs ──────────────────────────── */}
        {activeTab === 'architecture' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '1rem', color: '#06B6D4' }}>
                Unique Selling Propositions (USPs)
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                  <strong style={{ color: '#F8FAFC' }}>1. Contract-to-Behavior Trust Gap Analysis (ANN Rules)</strong>
                  <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Unlike traditional static-only scanners, AUDIT FORGE verifies whether an MCP tool’s declared annotations (readOnlyHint, openWorldHint, destructiveHint) honestly match actual observed static code capabilities and dynamic runtime telemetry.
                  </p>
                </div>

                <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                  <strong style={{ color: '#F8FAFC' }}>2. Multi-Layer Prompt Injection Detection</strong>
                  <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Layer 0 scans for zero-width Unicode characters and bidi overrides that deceive humans while injecting prompts to LLM agents. Layer 2 classifies semantic imperative overrides via Qwen3.
                  </p>
                </div>

                <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                  <strong style={{ color: '#F8FAFC' }}>3. Live Rug Pull & Drift Detection (DIFF Rules)</strong>
                  <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Cryptographic baseline pinning prevents tool supply-chain attacks. Once an auditor approves a server, any parameter addition or description mutation immediately revokes trust.
                  </p>
                </div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '1rem', color: '#4F46E5' }}>
                Hardened Dynamic Containment
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Probes execute under strict sandboxing as defined in Section 5.4 of the competition playbook:
              </p>
              <div className="code-box">
                <div>docker run --rm -i \</div>
                <div>  --network none \</div>
                <div>  --read-only \</div>
                <div>  --tmpfs /tmp:rw,noexec,nosuid,size=16m \</div>
                <div>  --memory=512m --cpus=1 --pids-limit=64 \</div>
                <div>  --cap-drop=ALL \</div>
                <div>  --security-opt=no-new-privileges \</div>
                <div>  --user=65532:65532 audit-forge-probe</div>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
                sys.addaudithook() provides non-invasive runtime telemetry to capture file writes, subprocesses, and network attempts.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        padding: '1rem 2rem',
        fontSize: '0.8rem',
        color: 'var(--text-muted)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>AUDIT FORGE © 2026 — PS02 MCP Security Auditor. Zero AI Slop. Real Evidence Traces.</div>
        <div>Compliant with AGENTS.md & Competition Playbook</div>
      </footer>
    </div>
  );
}
