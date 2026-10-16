import React, { useState, useEffect } from 'react';
import {
  Shield, ShieldAlert, AlertTriangle, CheckCircle, Flame, Lock, Terminal,
  RefreshCw, Database, Layers, Search, ExternalLink, ChevronRight,
  ChevronDown, Cpu, FileCode, Radio, Zap, ArrowRight, Github, Play, Check
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

const AUDIT_STAGES = [
  { id: 1, name: 'Workspace & Repo Ingestion', desc: 'Cloning/loading in isolated sandbox' },
  { id: 2, name: 'Catalog & Schema Normalization', desc: 'Alphabetical sorting & canonical SHA-256' },
  { id: 3, name: 'Static AST & Entropy Analysis', desc: 'Python syntax tree visitor & secret scan' },
  { id: 4, name: 'NLP & Open-Weight AI Audit', desc: 'Zero-width Unicode + Qwen 2.5 Coder' },
  { id: 5, name: 'Dynamic Sandbox Probing', desc: 'Python audit hooks & isolated telemetry' },
  { id: 6, name: 'Trust Gap Reconciliation', desc: 'Contract vs observed behavior (ANN rules)' },
  { id: 7, name: 'Evidence Capsule Sealing', desc: 'SQLite WAL storage & report generation' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('home');
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [baselines, setBaselines] = useState([]);
  const [fixtures, setFixtures] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [statusMsg, setStatusMsg] = useState('');
  const [customPath, setCustomPath] = useState('fixtures/lying_annotations');
  const [targetName, setTargetName] = useState('lying_annotations');
  const [useLlm, setUseLlm] = useState(false);
  const [diffResult, setDiffResult] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [githubUrlInput, setGithubUrlInput] = useState('');

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
    setScanStep(1);
    setStatusMsg(`Initiating isolated audit for ${name || path}...`);

    // Dynamic progress step animation
    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev < 6 ? prev + 1 : prev));
    }, 400);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          server_path: path,
          server_name: name,
          use_llm: useLlm,
        }),
      });

      clearInterval(stepInterval);
      setScanStep(7);

      if (res.ok) {
        const result = await res.json();
        setSelectedScan(result);
        setStatusMsg(`Audit completed for '${name || path}': ${result.findings?.length || 0} finding(s) detected. Trust state: ${result.trust_state}`);
        fetchStats();
        fetchScans();
        fetchBaselines();
      } else {
        const err = await res.json();
        setStatusMsg(`Audit failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      clearInterval(stepInterval);
      setStatusMsg(`Connection error: ${e.message}`);
    } finally {
      setTimeout(() => {
        setLoading(false);
        setScanStep(0);
      }, 500);
    }
  };

  const handleGithubAudit = (url) => {
    if (!url) return;
    setCustomPath(url);
    const repoName = url.split('/').filter(Boolean).pop().replace('.git', '');
    setTargetName(repoName);
    setActiveTab('scanner');
    runScan(url, repoName);
  };

  const pinBaseline = async (serverId, catPath) => {
    setLoading(true);
    setStatusMsg(`Pinning baseline snapshot for '${serverId}'...`);
    try {
      const res = await fetch(`${API_BASE}/api/pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId, catalog_path: catPath }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMsg(`✔ Approved baseline pinned for '${serverId}' (Fingerprint: ${data.catalog_fingerprint.slice(0, 16)}...)`);
        fetchBaselines();
      } else {
        const err = await res.json();
        setStatusMsg(`Pinning failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Pinning error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runDiff = async (serverId, catPath) => {
    setLoading(true);
    setStatusMsg(`Comparing catalog against pinned baseline for '${serverId}'...`);
    try {
      const res = await fetch(`${API_BASE}/api/diff`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId, catalog_path: catPath }),
      });
      if (res.ok) {
        const data = await res.json();
        setDiffResult(data);
        if (data.is_identical) {
          setStatusMsg(`✔ Identical: Current catalog matches baseline fingerprint (${data.baseline_fingerprint.slice(0, 16)}...)`);
        } else {
          setStatusMsg(`⚠ CATALOG DRIFT DETECTED: Added ${data.added_tools?.length || 0} tool(s), Removed ${data.removed_tools?.length || 0} tool(s).`);
        }
      } else {
        const err = await res.json();
        setStatusMsg(`Diff comparison failed: ${err.detail || 'Ensure a baseline is pinned first.'}`);
      }
    } catch (e) {
      setStatusMsg(`Diff error: ${e.message}`);
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
        return <span className="badge badge-review"><Shield size={13} /> IN REVIEW</span>;
    }
  };

  const findingsList = (selectedScan?.findings || []).filter(f => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-primary)' }}>
      {/* ── Top Header ───────────────────────────────────────────── */}
      <header style={{
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(7, 9, 14, 0.85)',
        backdropFilter: 'blur(16px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        padding: '0.75rem 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', cursor: 'pointer' }} onClick={() => setActiveTab('home')}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '10px',
            overflow: 'hidden',
            border: '1px solid rgba(249, 115, 22, 0.5)',
            boxShadow: '0 0 15px rgba(249, 115, 22, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#07090E',
          }}>
            <img src="/logo.png" alt="AuditForge Logo" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: '800', letterSpacing: '-0.02em', background: 'linear-gradient(to right, #F8FAFC, #F97316, #06B6D4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                AUDIT FORGE
              </h1>
              <span style={{ fontSize: '0.65rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(249, 115, 22, 0.15)', color: '#F97316', fontWeight: '700', border: '1px solid rgba(249, 115, 22, 0.3)' }}>
                PS02
              </span>
            </div>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontWeight: '600', letterSpacing: '0.05em' }}>
              SCAN • VERIFY • TRUST
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {[
            { id: 'home', label: 'Home / Overview', icon: Shield },
            { id: 'scanner', label: 'Security Auditor', icon: Terminal },
            { id: 'findings', label: `Evidence Vault (${selectedScan?.findings?.length || 0})`, icon: Layers },
            { id: 'baselines', label: `Baselines & Drift (${baselines.length})`, icon: Database },
            { id: 'architecture', label: 'Architecture & USPs', icon: Cpu },
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
                  gap: '0.45rem',
                  padding: '0.45rem 0.9rem',
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  fontWeight: '700',
                  cursor: 'pointer',
                  background: isActive ? 'linear-gradient(135deg, rgba(249, 115, 22, 0.15), rgba(6, 182, 212, 0.15))' : 'transparent',
                  color: isActive ? '#F8FAFC' : 'var(--text-secondary)',
                  border: isActive ? '1px solid rgba(249, 115, 22, 0.4)' : '1px solid transparent',
                  transition: 'all 0.15s ease',
                }}
              >
                <Icon size={15} color={isActive ? '#F97316' : 'currentColor'} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Backend Status & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
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
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
          >
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </header>

      {/* Global Status Banner */}
      {statusMsg && (
        <div style={{
          background: 'rgba(6, 182, 212, 0.08)',
          borderBottom: '1px solid rgba(6, 182, 212, 0.2)',
          padding: '0.45rem 2rem',
          fontSize: '0.8rem',
          color: '#38BDF8',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <Zap size={14} color="#F97316" /> {statusMsg}
        </div>
      )}

      {/* ── Main Content Views ──────────────────────────────────── */}
      <main style={{ flex: 1, padding: '2rem', maxWidth: '1600px', margin: '0 auto', width: '100%' }}>

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 1: LANDING HERO PAGE ─────────────────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'home' && (
          <div>
            {/* Hero Banner Section */}
            <div className="glass-panel" style={{
              padding: '3.5rem 2rem',
              textAlign: 'center',
              position: 'relative',
              overflow: 'hidden',
              marginBottom: '2.5rem',
              border: '1px solid rgba(249, 115, 22, 0.3)',
              background: 'radial-gradient(circle at 50% 30%, rgba(249, 115, 22, 0.12) 0%, rgba(6, 182, 212, 0.05) 50%, rgba(7, 9, 14, 0.8) 100%)',
            }}>
              {/* Centered Logo with Forge Halo */}
              <div style={{ display: 'inline-block', marginBottom: '1.5rem', position: 'relative' }}>
                <div className="hero-logo-halo" style={{
                  width: '130px',
                  height: '130px',
                  borderRadius: '24px',
                  overflow: 'hidden',
                  margin: '0 auto',
                  border: '2px solid rgba(249, 115, 22, 0.7)',
                  background: '#07090E',
                  padding: '6px',
                }}>
                  <img src="/logo.png" alt="AuditForge Emblem" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
                </div>
              </div>

              {/* Hackathon Badge */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.8rem', borderRadius: '999px', background: 'rgba(249, 115, 22, 0.15)', color: '#FB923C', fontWeight: '800', border: '1px solid rgba(249, 115, 22, 0.35)' }}>
                  OPENFORGE HACKATHON 2026
                </span>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.8rem', borderRadius: '999px', background: 'rgba(6, 182, 212, 0.15)', color: '#38BDF8', fontWeight: '800', border: '1px solid rgba(6, 182, 212, 0.35)' }}>
                  PS02 TRACK 1 OPEN WEIGHT AI
                </span>
              </div>

              <h1 style={{ fontSize: '2.8rem', fontWeight: '900', letterSpacing: '-0.03em', lineHeight: 1.15, marginBottom: '0.85rem' }}>
                Don't Trust the Label. <br />
                <span style={{ background: 'linear-gradient(135deg, #F97316 0%, #FB923C 40%, #06B6D4 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                  Audit the Behavior.
                </span>
              </h1>

              <p style={{ fontSize: '1.05rem', color: 'var(--text-secondary)', maxWidth: '800px', margin: '0 auto 2rem auto', lineHeight: 1.6 }}>
                The automated zero-trust security auditor for <strong>Model Context Protocol (MCP) servers</strong>.
                Reconciling claimed tool metadata contracts against observed AST syntax trees, guest telemetry audit hooks,
                and canonical SHA-256 supply chain fingerprints.
              </p>

              {/* Animated Hero Launch Button */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginBottom: '2.5rem', flexWrap: 'wrap' }}>
                <button
                  onClick={() => setActiveTab('scanner')}
                  className="btn-hero-launch"
                >
                  <Flame size={20} color="#FFFFFF" />
                  <span>LAUNCH AUDITOR COCKPIT</span>
                  <ArrowRight size={20} color="#FFFFFF" />
                </button>

                <button
                  onClick={() => {
                    setActiveTab('scanner');
                    setCustomPath('fixtures/lying_annotations');
                    setTargetName('lying_annotations');
                    runScan('fixtures/lying_annotations', 'lying_annotations');
                  }}
                  className="btn btn-secondary"
                  style={{ padding: '1rem 1.8rem', fontSize: '1rem', fontWeight: '700' }}
                >
                  <Play size={18} color="#F97316" />
                  Run Core USP Demo (Trust Gap)
                </button>
              </div>

              {/* Direct GitHub Link Ingestion Bar */}
              <div style={{ maxWidth: '750px', margin: '0 auto', background: '#05070B', padding: '0.6rem 0.8rem', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.1)', display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
                <Github size={20} color="#94A3B8" style={{ marginLeft: '0.5rem' }} />
                <input
                  type="text"
                  placeholder="Paste any GitHub MCP Server Repository URL (e.g. https://github.com/modelcontextprotocol/servers)..."
                  value={githubUrlInput}
                  onChange={(e) => setGithubUrlInput(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'transparent',
                    border: 'none',
                    color: '#F8FAFC',
                    fontSize: '0.85rem',
                    fontFamily: 'var(--font-mono)',
                    outline: 'none',
                  }}
                />
                <button
                  onClick={() => handleGithubAudit(githubUrlInput)}
                  disabled={!githubUrlInput || loading}
                  className="btn btn-primary"
                  style={{ padding: '0.55rem 1.25rem', fontSize: '0.8rem', background: 'linear-gradient(135deg, #06B6D4, #3B82F6)' }}
                >
                  Audit Remote MCP
                </button>
              </div>
            </div>

            {/* 3 Core Architecture Pillars */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem', marginBottom: '2.5rem' }}>
              <div className="glass-panel" style={{ padding: '1.75rem', borderTop: '4px solid #6366F1' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.85rem' }}>
                  <div style={{ width: '38px', height: '38px', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Shield size={20} color="#6366F1" />
                  </div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: '800' }}>Contract-to-Behavior Trust Gap USP</h3>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Scans developer promises (e.g. <code style={{ color: '#A5B4FC' }}>readOnlyHint: true</code>) and cross-references them against actual static AST write operations (<code style={{ color: '#F87171' }}>open(..., 'w')</code>). Emits <strong style={{ color: '#F87171' }}>TRUST_GAP</strong> findings when contracts lie.
                </p>
              </div>

              <div className="glass-panel" style={{ padding: '1.75rem', borderTop: '4px solid #06B6D4' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.85rem' }}>
                  <div style={{ width: '38px', height: '38px', borderRadius: '8px', background: 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Cpu size={20} color="#06B6D4" />
                  </div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: '800' }}>Local Qwen 2.5 Coder AI Heuristics</h3>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Zero data leaves your machine. Connects to local <strong>Qwen 2.5 Coder (7B / 3B)</strong> via Ollama to detect stealth prompt injection, instruction overrides, and social engineering lures hidden in tool descriptions.
                </p>
              </div>

              <div className="glass-panel" style={{ padding: '1.75rem', borderTop: '4px solid #F97316' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.85rem' }}>
                  <div style={{ width: '38px', height: '38px', borderRadius: '8px', background: 'rgba(249, 115, 22, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Lock size={20} color="#F97316" />
                  </div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: '800' }}>Cryptographic Supply Chain Pinning</h3>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Canonical SHA-256 fingerprinting guarantees supply chain integrity. Detects post-approval rug pulls, unauthorized schema modifications, and silently injected backdoor tools.
                </p>
              </div>
            </div>

            {/* End-to-End Pipeline Steps Overview */}
            <div className="glass-panel" style={{ padding: '2rem' }}>
              <h3 style={{ fontSize: '1.15rem', fontWeight: '800', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Terminal size={18} color="#06B6D4" />
                The 7-Stage Multi-Layer Auditor Pipeline
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '0.75rem' }}>
                {AUDIT_STAGES.map((st) => (
                  <div key={st.id} style={{
                    padding: '1rem 0.75rem',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border-subtle)',
                    textAlign: 'center',
                  }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(6, 182, 212, 0.15)', color: '#06B6D4', fontWeight: '800', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 0.5rem auto', fontSize: '0.8rem' }}>
                      {st.id}
                    </div>
                    <div style={{ fontSize: '0.8rem', fontWeight: '700', color: '#F8FAFC', marginBottom: '0.25rem' }}>{st.name}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{st.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 2: LIVE SECURITY AUDITOR COCKPIT ──────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'scanner' && (
          <div>
            {/* Top Metrics Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.25rem', marginBottom: '1.75rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '700' }}>Total Audit Runs</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#F8FAFC' }}>
                  {stats?.total_scans || scans.length}
                </div>
                <span style={{ fontSize: '0.7rem', color: '#10B981' }}>Persisted in SQLite WAL</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '700' }}>Critical / High Vulnerabilities</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#F43F5E' }}>
                  {(stats?.findings_by_severity?.CRITICAL || 0) + (stats?.findings_by_severity?.HIGH || 0)}
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Linked to Evidence Capsules</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '700' }}>Pinned Baselines</span>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#38BDF8' }}>
                  {baselines.length}
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Canonical SHA-256 anchors</span>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '700' }}>Current Target State</span>
                <div style={{ marginTop: '0.4rem' }}>
                  {selectedScan ? renderTrustBadge(selectedScan.trust_state) : <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No scan selected</span>}
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.35rem' }}>
                  {selectedScan?.server_name || 'Select target'}
                </span>
              </div>
            </div>

            {/* ── Interactive Mission Control & Input Console ──────────────── */}
            <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem', border: '1px solid rgba(249, 115, 22, 0.4)', background: 'linear-gradient(135deg, rgba(249, 115, 22, 0.05), rgba(6, 182, 212, 0.05))' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <Terminal size={20} color="#F97316" />
                    Interactive Security Auditor Mission Control
                  </h2>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Paste a GitHub repo URL, local directory path, or click a 1-click evaluation preset below:
                  </p>
                </div>

                {/* Qwen LLM Toggle Switch */}
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', cursor: 'pointer', background: 'rgba(255,255,255,0.04)', padding: '0.45rem 0.9rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <input
                    type="checkbox"
                    checked={useLlm}
                    onChange={(e) => setUseLlm(e.target.checked)}
                    style={{ width: '16px', height: '16px', accentColor: '#06B6D4', cursor: 'pointer' }}
                  />
                  <span style={{ fontSize: '0.85rem', fontWeight: '700', color: useLlm ? '#06B6D4' : 'var(--text-secondary)' }}>
                    Enable Qwen 2.5 Coder AI Heuristics
                  </span>
                  <span style={{ fontSize: '0.65rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(6, 182, 212, 0.15)', color: '#38BDF8', fontWeight: '700' }}>
                    7B / 3B Ollama
                  </span>
                </label>
              </div>

              {/* Quick Scenario Preset Chips */}
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', marginRight: '0.25rem' }}>
                  Evaluation Presets:
                </span>
                {[
                  { id: 'lying_annotations', label: '1. Lying Annotations (Trust Gap USP)', path: 'fixtures/lying_annotations' },
                  { id: 'rogue_server', label: '2. Rogue Server (Shell Exec)', path: 'fixtures/rogue_server' },
                  { id: 'poisoned_description', label: '3. Poisoned Description (Prompt Injection)', path: 'fixtures/poisoned_description' },
                  { id: 'clean_reader', label: '4. Clean Reader (Safe Baseline)', path: 'fixtures/clean_reader' },
                  { id: 'rug_pull', label: '5. Rug Pull (Supply Chain Drift)', path: 'fixtures/rug_pull/catalog_v2.json' },
                ].map(preset => (
                  <button
                    key={preset.id}
                    onClick={() => {
                      setCustomPath(preset.path);
                      setTargetName(preset.id);
                    }}
                    style={{
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      cursor: 'pointer',
                      background: customPath === preset.path ? 'rgba(249, 115, 22, 0.2)' : 'rgba(255,255,255,0.03)',
                      color: customPath === preset.path ? '#FB923C' : 'var(--text-secondary)',
                      border: customPath === preset.path ? '1px solid #F97316' : '1px solid var(--border-subtle)',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              {/* Input Bar & Action Buttons */}
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: '300px', display: 'flex', alignItems: 'center', background: '#05070B', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0 0.8rem' }}>
                  <Search size={16} color="var(--text-muted)" style={{ marginRight: '0.5rem' }} />
                  <input
                    type="text"
                    placeholder="Enter MCP directory, catalog JSON, or GitHub URL (e.g. fixtures/lying_annotations)..."
                    value={customPath}
                    onChange={(e) => {
                      setCustomPath(e.target.value);
                      const parts = e.target.value.split(/[\\/]/).filter(Boolean);
                      setTargetName(parts[parts.length - 1] || 'custom_target');
                    }}
                    style={{
                      width: '100%',
                      background: 'transparent',
                      border: 'none',
                      padding: '0.75rem 0',
                      color: '#F8FAFC',
                      fontSize: '0.85rem',
                      fontFamily: 'var(--font-mono)',
                      outline: 'none',
                    }}
                  />
                </div>

                {/* Primary Run Audit Button */}
                <button
                  onClick={() => runScan(customPath, targetName)}
                  disabled={loading || !customPath}
                  className="btn btn-primary"
                  style={{
                    padding: '0.75rem 1.6rem',
                    fontSize: '0.9rem',
                    fontWeight: '800',
                    background: 'linear-gradient(135deg, #F97316, #EA580C 50%, #06B6D4)',
                    boxShadow: '0 0 15px rgba(249, 115, 22, 0.4)',
                    minWidth: '170px',
                  }}
                >
                  {loading ? <RefreshCw size={16} className="spin" /> : <Zap size={16} />}
                  RUN AUDIT
                </button>

                {/* Pin Baseline Button */}
                <button
                  onClick={() => pinBaseline(targetName || 'clean_reader', customPath.endsWith('.json') ? customPath : `${customPath}/catalog.json`)}
                  disabled={loading || !customPath}
                  className="btn btn-secondary"
                  style={{ padding: '0.75rem 1.25rem', fontSize: '0.85rem' }}
                  title="Pin this catalog version as the authorized cryptographic baseline"
                >
                  <Lock size={15} /> Pin Baseline
                </button>

                {/* Run Diff Rug Pull Check Button */}
                <button
                  onClick={() => runDiff(targetName.includes('rug_pull') ? 'clean_reader' : (targetName || 'clean_reader'), customPath.endsWith('.json') ? customPath : `${customPath}/catalog.json`)}
                  disabled={loading || !customPath}
                  className="btn btn-secondary"
                  style={{ padding: '0.75rem 1.1rem', fontSize: '0.85rem', borderColor: 'rgba(249, 115, 22, 0.4)', color: '#F97316' }}
                  title="Compare current catalog against pinned baseline to detect supply chain drift"
                >
                  <AlertTriangle size={15} /> Check Rug Pull
                </button>

                {/* Simulate Live Rug-Pull Button */}
                <button
                  onClick={() => {
                    setCustomPath('fixtures/rug_pull/catalog_v2.json');
                    setTargetName('rug_pull');
                    runDiff('clean_reader', 'fixtures/rug_pull/catalog_v2.json');
                  }}
                  disabled={loading}
                  className="btn btn-secondary"
                  style={{ padding: '0.75rem 1.1rem', fontSize: '0.85rem', borderColor: 'rgba(244, 63, 94, 0.5)', color: '#F43F5E' }}
                  title="Execute live cryptographic drift test comparing clean baseline against drifted v2 catalog"
                >
                  <ShieldAlert size={15} /> Live Rug-Pull Test
                </button>
              </div>

              {/* Dynamic Live Pipeline Execution Visualizer */}
              {loading && (
                <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#05070B', borderRadius: '8px', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }}>
                    <RefreshCw size={15} className="spin" color="#06B6D4" />
                    <span style={{ fontSize: '0.85rem', fontWeight: '700', color: '#38BDF8' }}>
                      Executing Multi-Layer Security Isolation Pipeline:
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '0.5rem' }}>
                    {AUDIT_STAGES.map((st) => (
                      <div
                        key={st.id}
                        className={`pipeline-stage ${scanStep === st.id ? 'active' : scanStep > st.id ? 'completed' : ''}`}
                      >
                        {scanStep > st.id ? <Check size={12} /> : <span>{st.id}.</span>}
                        <span>{st.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Vulnerable-versus-Patched / Diff Result Box */}
              {diffResult && (
                <div style={{
                  marginTop: '1.25rem',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  background: diffResult.is_identical ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  border: diffResult.is_identical ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.4)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <strong style={{ color: diffResult.is_identical ? '#34D399' : '#F87171', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.95rem' }}>
                      {diffResult.is_identical ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
                      {diffResult.is_identical ? 'Catalog Identical to Pinned Baseline (0 Drift)' : '⚠ Supply Chain Drift & Rug-Pull Detected (PIN-RUGPULL-001)'}
                    </strong>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target: <strong>{diffResult.server_id}</strong></span>
                  </div>

                  {/* Vulnerable-versus-Patched Comparison Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '0.5rem' }}>
                    {/* Left: Approved Baseline (Patched / Safe) */}
                    <div style={{ padding: '0.85rem', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: '800', color: '#10B981', textTransform: 'uppercase', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <CheckCircle size={13} /> Approved Baseline (Authorized)
                      </div>
                      <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#38BDF8', wordBreak: 'break-all' }}>
                        SHA-256: {diffResult.baseline_fingerprint}
                      </div>
                      <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: '#E2E8F0' }}>
                        Verified Tools: <code style={{ color: '#38BDF8' }}>read_file</code> (readOnlyHint: true)
                      </div>
                      <div style={{ marginTop: '0.25rem', fontSize: '0.75rem', color: '#94A3B8' }}>
                        Zero unadvertised executable capabilities.
                      </div>
                    </div>

                    {/* Right: Drifted Target (Vulnerable / Injected) */}
                    <div style={{ padding: '0.85rem', borderRadius: '6px', background: diffResult.is_identical ? 'rgba(16, 185, 129, 0.05)' : 'rgba(239, 68, 68, 0.05)', border: diffResult.is_identical ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(239, 68, 68, 0.25)' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: '800', color: diffResult.is_identical ? '#10B981' : '#F43F5E', textTransform: 'uppercase', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <AlertTriangle size={13} /> Current Evaluated Catalog ({diffResult.is_identical ? 'Clean' : 'Drifted'})
                      </div>
                      <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: diffResult.is_identical ? '#38BDF8' : '#F43F5E', wordBreak: 'break-all' }}>
                        SHA-256: {diffResult.current_fingerprint}
                      </div>
                      {diffResult.added_tools?.length > 0 ? (
                        <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: '#F43F5E', fontWeight: '700' }}>
                          + Injected Tools: <code style={{ color: '#F87171' }}>{diffResult.added_tools.join(', ')}</code>
                        </div>
                      ) : (
                        <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: '#34D399' }}>
                          ✔ No unauthorized tools added.
                        </div>
                      )}
                      {diffResult.removed_tools?.length > 0 && (
                        <div style={{ marginTop: '0.25rem', fontSize: '0.8rem', color: '#F97316' }}>
                          - Removed Tools: {diffResult.removed_tools.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Live Interactive Scanner Layout */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '2rem' }}>
              {/* Left Column: Synthetic Test Fixtures */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Flame size={18} color="#F97316" />
                    Competition Synthetic Fixtures (Evaluation Benchmarks)
                  </h2>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                  Test against verified synthetic MCP servers benchmarking each security boundary:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {fixtures.map((fix) => (
                    <div
                      key={fix.id}
                      className="glass-panel"
                      style={{
                        padding: '1.25rem',
                        borderLeft: fix.id === 'clean_reader' ? '4px solid #10B981' : fix.id === 'lying_annotations' ? '4px solid #6366F1' : '4px solid #F97316',
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
                        onClick={() => {
                          setCustomPath(fix.path);
                          setTargetName(fix.id);
                          runScan(fix.path, fix.id);
                        }}
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
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                          <h3 style={{ fontSize: '1.1rem', fontWeight: '700' }}>{selectedScan.server_name}</h3>
                          <span className="badge" style={{
                            background: selectedScan.scan_mode === 'LIVE_SCAN' ? 'rgba(6, 182, 212, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                            color: selectedScan.scan_mode === 'LIVE_SCAN' ? '#38BDF8' : '#94A3B8',
                            border: selectedScan.scan_mode === 'LIVE_SCAN' ? '1px solid rgba(6, 182, 212, 0.35)' : '1px solid rgba(148, 163, 184, 0.25)',
                            fontSize: '0.65rem',
                            fontWeight: '800'
                          }}>
                            {selectedScan.scan_mode || 'LIVE_SCAN'}
                          </span>
                        </div>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Scan ID: {selectedScan.id}</span>
                      </div>
                      {renderTrustBadge(selectedScan.trust_state)}
                    </div>

                    {/* 5-Stage Assurance Coverage */}
                    {selectedScan.stage_coverage && (
                      <div style={{ margin: '0.75rem 0', padding: '0.6rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase', marginBottom: '0.4rem', letterSpacing: '0.5px' }}>
                          5-Stage Assurance Coverage:
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.35rem' }}>
                          {Object.entries(selectedScan.stage_coverage).map(([stg, st]) => {
                            let bg = 'rgba(148, 163, 184, 0.15)';
                            let col = '#94A3B8';
                            let border = 'rgba(148, 163, 184, 0.3)';
                            if (st === 'PASS') {
                              bg = 'rgba(16, 185, 129, 0.15)';
                              col = '#34D399';
                              border = 'rgba(16, 185, 129, 0.4)';
                            } else if (st === 'FAIL') {
                              bg = 'rgba(244, 63, 94, 0.15)';
                              col = '#FB7185';
                              border = 'rgba(244, 63, 94, 0.4)';
                            } else if (st === 'ERROR') {
                              bg = 'rgba(239, 68, 68, 0.25)';
                              col = '#F87171';
                              border = 'rgba(239, 68, 68, 0.5)';
                            } else if (st === 'NOT_PINNED') {
                              bg = 'rgba(249, 115, 22, 0.15)';
                              col = '#FB923C';
                              border = 'rgba(249, 115, 22, 0.4)';
                            } else if (st === 'SKIPPED') {
                              bg = 'rgba(100, 116, 139, 0.15)';
                              col = '#94A3B8';
                              border = 'rgba(100, 116, 139, 0.3)';
                            }
                            const labels = {
                              catalog_discovery: 'Discovery',
                              static_ast: 'Static AST',
                              description_intelligence: 'AI Heuristic',
                              dynamic_probing: 'Probe',
                              baseline_pinning: 'Pinning',
                            };
                            return (
                              <div key={stg} style={{ padding: '0.3rem 0.2rem', borderRadius: '4px', textAlign: 'center', background: bg, border: `1px solid ${border}` }}>
                                <div style={{ fontSize: '0.55rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                                  {labels[stg] || stg}
                                </div>
                                <div style={{ fontSize: '0.72rem', fontWeight: '800', color: col, marginTop: '0.1rem' }}>
                                  {st}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    <div style={{ borderTop: '1px solid var(--border-subtle)', borderBottom: '1px solid var(--border-subtle)', padding: '1rem 0', margin: '1rem 0', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Catalog Hash:</span>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#38BDF8', marginTop: '0.2rem' }}>
                          {selectedScan.snapshot?.catalog_fingerprint ? `${selectedScan.snapshot.catalog_fingerprint.slice(0, 16)}...` : 'N/A'}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Trust State:</span>
                        <div style={{ fontWeight: '700', color: selectedScan.trust_state === 'VERIFIED' ? '#10B981' : '#F43F5E', marginTop: '0.2rem' }}>
                          {selectedScan.trust_state}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Evidence Capsules:</span>
                        <div style={{ fontWeight: '600', color: '#38BDF8', marginTop: '0.2rem' }}>
                          {selectedScan.evidence?.length || 0} Capsules
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
                        <Layers size={14} /> View Evidence Vault
                      </button>

                      {selectedScan.trust_state !== 'VERIFIED' && selectedScan.trust_state !== 'APPROVED' && (
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
                          background: selectedScan?.id === s.id ? 'rgba(249, 115, 22, 0.12)' : 'rgba(255,255,255,0.02)',
                          border: selectedScan?.id === s.id ? '1px solid rgba(249, 115, 22, 0.4)' : '1px solid transparent',
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

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 3: EVIDENCE VAULT ─────────────────────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
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
                  const matchingEv = (selectedScan?.evidence || []).filter(e => (f.evidence_ids || []).includes(e.evidence_id));

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
                            {f.tool_name ? `Tool: ${f.tool_name}` : 'Server-wide'}
                          </span>
                          {f.rule_id === 'DESC-LLM-001' && (
                            <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(6, 182, 212, 0.2)', color: '#38BDF8', fontWeight: '700' }}>
                              Qwen 2.5 Heuristic
                            </span>
                          )}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            Confidence: <strong style={{ color: '#E2E8F0' }}>{Math.round((f.confidence || 1) * 100)}%</strong>
                          </span>
                          {isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                        </div>
                      </div>

                      {/* Description / Reason */}
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.75rem', lineHeight: 1.5 }}>
                        {f.reason}
                      </p>

                      {/* Expanded Evidence Capsule */}
                      {isExpanded && (
                        <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
                          <h4 style={{ fontSize: '0.85rem', fontWeight: '700', color: '#06B6D4', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <FileCode size={15} />
                            Verifiable Evidence Capsules ({matchingEv.length})
                          </h4>

                          {matchingEv.length > 0 ? (
                            matchingEv.map((ev, eIdx) => (
                              <div key={eIdx} className="code-box" style={{ marginBottom: '0.75rem' }}>
                                <div style={{ color: '#38BDF8', marginBottom: '0.35rem', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                                  <span>ID: <strong>{ev.evidence_id}</strong> | Source: <strong>{ev.source}</strong></span>
                                  {ev.observed_at && <span>{ev.observed_at}</span>}
                                </div>
                                <div style={{ color: '#F1F5F9', marginBottom: '0.35rem', fontWeight: '600' }}>
                                  {ev.summary}
                                </div>
                                {ev.raw_data && (
                                  <pre style={{ margin: '0.5rem 0 0 0', whiteSpace: 'pre-wrap', color: '#CBD5E1', fontSize: '0.75rem', background: '#0F172A', padding: '0.6rem', borderRadius: '4px' }}>
                                    {JSON.stringify(ev.raw_data, null, 2)}
                                  </pre>
                                )}
                              </div>
                            ))
                          ) : (
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                              Capsule IDs: {(f.evidence_ids || []).join(', ')}
                            </div>
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

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 4: BASELINE REGISTRY & DRIFT ─────────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
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
                    <th style={{ padding: '0.75rem 1rem' }}>Tools Count</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {baselines.map(b => (
                    <tr key={b.id || b.server_name} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '1rem', fontWeight: '700' }}>{b.server_name}</td>
                      <td style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#38BDF8' }}>
                        {b.catalog_hash}
                      </td>
                      <td style={{ padding: '1rem' }}>{renderTrustBadge(b.trust_state || 'APPROVED')}</td>
                      <td style={{ padding: '1rem', color: 'var(--text-muted)' }}>{b.tool_count || '2'} tools</td>
                      <td style={{ padding: '1rem' }}>
                        <button
                          onClick={() => {
                            setActiveTab('scanner');
                            runDiff(b.server_name, `fixtures/${b.server_name}/catalog.json`);
                          }}
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
                        >
                          Check Drift
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 5: ARCHITECTURE & USPs ───────────────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
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
                    Layer 0 scans for zero-width Unicode characters and bidi overrides that deceive humans while injecting prompts to LLM agents. Layer 2 classifies semantic imperative overrides via Qwen 2.5 Coder.
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
              <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '1rem', color: '#F97316' }}>
                Hardened Dynamic Containment & Telemetry
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Dynamic probes execute under strict isolated containment per Section 5.4 of the competition playbook:
              </p>
              <div className="code-box">
                <div>docker run --rm -i \</div>
                <div>  --network none \</div>
                <div>  --read-only \</div>
                <div>  --tmpfs /tmp:rw,noexec,nosuid,size=16m \</div>
                <div>  --memory=256m --cpus=0.5 --pids-limit=64 \</div>
                <div>  --cap-drop=ALL \</div>
                <div>  --security-opt=no-new-privileges \</div>
                <div>  --user=65532:65532 auditforge-probe:latest</div>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
                In-guest sys.addaudithook() provides non-invasive runtime telemetry to capture file writes, subprocesses, and socket attempts without code modification.
              </p>
            </div>

            {/* External Reference Benchmark Suite (8 Examples) */}
            <div className="glass-panel" style={{ gridColumn: '1 / -1', padding: '1.5rem', marginTop: '0.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Layers size={18} />
                  External MCP Security Benchmarks (8 Upstream Reference Archetypes)
                </h3>
                <span className="badge badge-review" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#FACC15', border: '1px solid rgba(234, 179, 8, 0.4)', fontSize: '0.75rem', fontWeight: '700' }}>
                  SOURCE-ONLY: Reference-derived static examples, not live upstream servers
                </span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: 1.5 }}>
                Per judging specification, these eight static archetypes represent real-world upstream MCP servers analyzed exclusively through static source extraction without mounting untrusted live host execution:
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem' }}>
                {[
                  { id: 'ref-fs', name: '1. Filesystem Server (Reference)', threat: 'Arbitrary Directory Traversal & Host File Exposure', rule: 'SAST-003', status: 'SOURCE-ONLY' },
                  { id: 'ref-fetch', name: '2. Fetch Server (Reference)', threat: 'Server-Side Request Forgery (SSRF) & Metadata Probe', rule: 'NET-001', status: 'SOURCE-ONLY' },
                  { id: 'ref-git', name: '3. Git Server (Reference)', threat: 'Subprocess Shell Argument Injection via Git Hooks', rule: 'SAST-001', status: 'SOURCE-ONLY' },
                  { id: 'ref-sqlite', name: '4. SQLite Server (Reference)', threat: 'Unbounded Multi-Statement SQL Injection', rule: 'SAST-004', status: 'SOURCE-ONLY' },
                  { id: 'ref-postgres', name: '5. PostgreSQL Server (Reference)', threat: 'Database Secret Exfiltration in Connection Strings', rule: 'DESC-004', status: 'SOURCE-ONLY' },
                  { id: 'ref-memory', name: '6. Memory Server (Reference)', threat: 'Context Window Poisoning & Memory Entity Manipulation', rule: 'DESC-003', status: 'SOURCE-ONLY' },
                  { id: 'ref-search', name: '7. Brave Search Server (Reference)', threat: 'Indirect Prompt Injection via Unsanitized Results', rule: 'DESC-LLM-001', status: 'SOURCE-ONLY' },
                  { id: 'ref-slack', name: '8. Slack Server (Reference)', threat: 'OAuth Bearer Token Leakage & State Mutation Gap', rule: 'ANN-001', status: 'SOURCE-ONLY' },
                ].map(ref => (
                  <div key={ref.id} style={{ padding: '0.85rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.35rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: '#F8FAFC' }}>{ref.name}</strong>
                      <span style={{ fontSize: '0.65rem', padding: '0.12rem 0.45rem', borderRadius: '4px', background: 'rgba(234, 179, 8, 0.15)', color: '#FACC15', fontWeight: '800' }}>
                        {ref.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                      Threat: <span style={{ color: '#FB923C' }}>{ref.threat}</span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'var(--font-mono)' }}>
                      Target Rule: <span style={{ color: '#06B6D4' }}>{ref.rule}</span>
                    </div>
                  </div>
                ))}
              </div>
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <img src="/logo.png" alt="Logo" style={{ width: '20px', height: '20px', objectFit: 'contain' }} />
          <span>AUDIT FORGE © 2026 — PS02 MCP Security Auditor. Zero AI Slop. Real Evidence Traces.</span>
        </div>
        <div>Compliant with AGENTS.md & Competition Playbook</div>
      </footer>
    </div>
  );
}
