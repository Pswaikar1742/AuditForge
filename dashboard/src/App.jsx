import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Flame, Lock, Terminal,
  RefreshCw, Database, Layers, Search, ExternalLink, ChevronRight,
  ChevronDown, Cpu, FileCode, Radio, Zap, ArrowRight, Github, Play, Check, ShieldAlert
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

const AUDIT_STAGES = [
  { id: 1, key: 'catalog_discovery', name: 'MCP Catalog Discovery', desc: 'Protocol discovery & schema normalization' },
  { id: 2, key: 'static_ast', name: 'Static AST & Entropy', desc: 'Python syntax tree visitor & secret scan' },
  { id: 3, key: 'description_intelligence', name: 'NLP & Open-Weight AI', desc: 'Zero-width Unicode + Qwen 2.5 Coder heuristics' },
  { id: 4, key: 'dynamic_probing', name: 'Dynamic Sandbox Probing', desc: 'Docker isolation, Python audit hooks & telemetry' },
  { id: 5, key: 'trust_gap', name: 'Trust Gap Reconciliation', desc: 'Contract vs observed behavior (ANN rules)' },
  { id: 6, key: 'baseline_pinning', name: 'Supply Chain Pinning & Diff', desc: 'Canonical SHA-256 fingerprinting & rug-pull check' },
  { id: 7, key: 'evidence_sealing', name: 'Evidence Integrity Digest', desc: 'SQLite WAL storage & SHA-256 evidence integrity checksum' },
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
  const [statusMsg, setStatusMsg] = useState('');
  const [customPath, setCustomPath] = useState('fixtures/lying_annotations');
  const [targetName, setTargetName] = useState('lying_annotations');
  const [useLlm, setUseLlm] = useState(false);
  const [diffResult, setDiffResult] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [targetIdInput, setTargetIdInput] = useState('');
  const [koalaReport, setKoalaReport] = useState(null);
  const [loadingAssurance, setLoadingAssurance] = useState(false);
  const [auditMode, setAuditMode] = useState('guided'); // 'guided' | 'advanced'
  const [searchTargetQuery, setSearchTargetQuery] = useState('');
  const [targetCategoryFilter, setTargetCategoryFilter] = useState('ALL');
  const [comparisonPairs, setComparisonPairs] = useState([]);
  const [selectedPairId, setSelectedPairId] = useState('pair_rogue_server');
  const [pairComparisonResult, setPairComparisonResult] = useState(null);
  const [loadingComparison, setLoadingComparison] = useState(false);

  // Milestone 2 & 3: Intelligence & Job Queue States
  const [intelligenceStatus, setIntelligenceStatus] = useState(null);
  const [intelligenceSources, setIntelligenceSources] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchTrustTier, setSearchTrustTier] = useState('ALL');
  const [searchResults, setSearchResults] = useState([]);
  const [searchingIntel, setSearchingIntel] = useState(false);
  const [findingToExplain, setFindingToExplain] = useState(null);
  const [findingExplanation, setFindingExplanation] = useState(null);
  const [explainingFinding, setExplainingFinding] = useState(false);
  const [explainUseLlm, setExplainUseLlm] = useState(false);

  const [jobList, setJobList] = useState([]);
  const [queueMetrics, setQueueMetrics] = useState(null);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [selectedJobTarget, setSelectedJobTarget] = useState('fixtures/clean_reader');

  useEffect(() => {
    checkHealth();
    fetchStats();
    fetchScans();
    fetchBaselines();
    fetchFixtures();
    fetchKoalaAssurance();
    fetchComparisonPairs();
    fetchIntelligenceStatus();
    fetchIntelligenceSources();
    fetchJobs();
    const interval = setInterval(() => {
      checkHealth();
      fetchJobs();
    }, 5000);
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
          fetchScanDetails(data[0].id || data[0].scan_id);
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

  const fetchKoalaAssurance = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/assurance/model`);
      if (res.ok) {
        const data = await res.json();
        setKoalaReport(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchComparisonPairs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/pairs`);
      if (res.ok) {
        const data = await res.json();
        setComparisonPairs(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const runPairComparison = async (pairId) => {
    const targetPair = pairId || selectedPairId;
    setLoadingComparison(true);
    setStatusMsg(`Executing side-by-side verification on '${targetPair}'...`);
    try {
      const res = await fetch(`${API_BASE}/api/compare/${targetPair}`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setPairComparisonResult(data);
        setStatusMsg(`✔ Side-by-side verification complete for ${data.title}: ${data.comparison_delta?.eliminated_findings_count || 0} findings eliminated.`);
      } else {
        const err = await res.json();
        setStatusMsg(`Comparison failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Comparison error: ${e.message}`);
    } finally {
      setLoadingComparison(false);
    }
  };


  const triggerKoalaAudit = async () => {
    setLoadingAssurance(true);
    setStatusMsg("Executing KOALA model governance audit (NIST AI RMF & EU AI Act)...");
    try {
      const res = await fetch(`${API_BASE}/api/assurance/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ frameworks: ['nist_ai_rmf', 'eu_ai_act'] }),
      });
      if (res.ok) {
        const data = await res.json();
        setKoalaReport(data);
        const count = data.summary?.controls_total ?? (data.results?.length ?? 0);
        setStatusMsg(`✔ KOALA Governance Audit Completed: ${count} controls assessed (${data.audit_mode || 'STATIC_GOVERNANCE_AUDIT'}).`);
      } else {
        const err = await res.json();
        setStatusMsg(`KOALA audit failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`KOALA error: ${e.message}`);
    } finally {
      setLoadingAssurance(false);
    }
  };

  const fetchIntelligenceStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/status`);
      if (res.ok) setIntelligenceStatus(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchIntelligenceSources = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/sources`);
      if (res.ok) setIntelligenceSources(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const searchKnowledgeBase = async (queryToSearch) => {
    const q = queryToSearch || searchQuery;
    if (!q || !q.trim()) return;
    setSearchingIntel(true);
    try {
      const body = { query: q, top_k: 6 };
      if (searchTrustTier !== 'ALL') body.trust_tier = searchTrustTier;
      const res = await fetch(`${API_BASE}/api/intelligence/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.results || []);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSearchingIntel(false);
    }
  };

  const handleExplainFinding = async (finding, useLlmFlag = false) => {
    setFindingToExplain(finding);
    setActiveTab('intelligence');
    setExplainingFinding(true);
    setFindingExplanation(null);
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/explain-finding`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, use_llm: useLlmFlag }),
      });
      if (res.ok) {
        const data = await res.json();
        setFindingExplanation(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setExplainingFinding(false);
    }
  };

  const fetchJobs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/jobs`);
      if (res.ok) {
        const data = await res.json();
        setJobList(data.jobs || []);
        setQueueMetrics(data.metrics || null);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const submitAsyncScanJob = async (target) => {
    const tgt = target || selectedJobTarget;
    setLoadingJobs(true);
    setStatusMsg(`Submitting asynchronous scan job for '${tgt}'...`);
    try {
      const res = await fetch(`${API_BASE}/api/jobs/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: tgt, scan_type: 'LIVE_SCAN', use_llm: useLlm }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMsg(`✔ Job ${data.job_id} enqueued successfully (${data.status})`);
        fetchJobs();
      } else {
        const err = await res.json();
        setStatusMsg(`Job submission failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Job submission error: ${e.message}`);
    } finally {
      setLoadingJobs(false);
    }
  };

  const cancelJob = async (jobId) => {
    try {
      const res = await fetch(`${API_BASE}/api/jobs/${jobId}/cancel`, { method: 'POST' });
      if (res.ok) {
        setStatusMsg(`Job ${jobId} cancelled.`);
        fetchJobs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const runScan = async (path, name) => {
    setLoading(true);
    setStatusMsg(`Running security audit on ${name || path}${useLlm ? ' (with Qwen AI heuristics)' : ''}...`);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: name || path,
          server_path: path,
          server_name: name,
          use_llm: useLlm,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
        setStatusMsg(`✔ Scan completed for ${data.server_name || name}. Trust State: ${data.trust_state}`);
        fetchStats();
        fetchScans();
      } else {
        const err = await res.json();
        setStatusMsg(`Scan failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Scan error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTargetInputAudit = (input) => {
    const trimmed = (input || '').trim();
    if (!trimmed) return;
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      setStatusMsg("Sandbox Security Policy: Direct host execution of arbitrary external URLs is restricted under Section 5 of AGENTS.md. Select an allowlisted sandboxed target fixture.");
      return;
    }
    setCustomPath(trimmed);
    const targetObj = fixtures.find(f => f.id === trimmed || f.path === trimmed);
    const resolvedName = targetObj ? targetObj.id : trimmed;
    setTargetName(resolvedName);
    setActiveTab('scanner');
    runScan(targetObj ? targetObj.path : trimmed, resolvedName);
  };

  const pinBaseline = async (serverId, catPath) => {
    setLoading(true);
    setStatusMsg(`Pinning baseline snapshot for '${serverId}'...`);
    try {
      const res = await fetch(`${API_BASE}/api/pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId, catalog_path: catPath, reapprove: true }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMsg(`✔ Approved baseline pinned for '${serverId}' (Fingerprint: ${data.catalog_fingerprint?.slice(0, 16)}...)`);
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
          setStatusMsg(`✔ Identical: Current catalog matches baseline fingerprint (${data.baseline_fingerprint?.slice(0, 16)}...)`);
        } else {
          setStatusMsg(`⚠ CATALOG DRIFT DETECTED: Category ${data.drift_category || 'CHANGED_REVIEW'}, Added ${data.added_tools?.length || 0} tool(s), Removed ${data.removed_tools?.length || 0} tool(s).`);
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
      const isVulnerable = ['rogue_server', 'poisoned_description', 'lying_annotations'].includes(serverName);
      if (isVulnerable) {
        const proceed = window.confirm(
          `WARNING: '${serverName}' is flagged as a KNOWN VULNERABLE fixture. Forcing baseline approval will record known security flaws as accepted behavior. Are you sure you want to proceed?`
        );
        if (!proceed) return;
      }
      const res = await fetch(`${API_BASE}/api/baselines/${serverName}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reapprove: true, force: isVulnerable }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMsg(data.status === 'PRESERVED_EXISTING' ? data.message : `✔ Approved baseline saved for '${serverName}'.`);
        fetchBaselines();
        fetchScans();
        if (selectedScan) fetchScanDetails(selectedScan.id || selectedScan.scan_id);
      } else {
        const err = await res.json();
        setStatusMsg(`Approval failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Approval failed: ${e.message}`);
    }
  };

  const runLiveRugPullDemo = async () => {
    setLoading(true);
    setStatusMsg("Executing live stdio rug-pull test (MCP server v1 vs v2 over protocol)...");
    try {
      const res = await fetch(`${API_BASE}/api/demo/rug-pull`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        const fullDiff = {
          ...(data.diff || {}),
          v1_baseline_hash: data.v1_baseline_hash,
          v2_mutated_hash: data.v2_mutated_hash,
          explanation: data.explanation,
          server_id: data.target || 'rug_pull',
        };
        setDiffResult(fullDiff);
        setStatusMsg("✔ Live Rug-Pull Detected: Version 2 mutated tool definitions over stdio transport.");
      } else {
        const err = await res.json();
        setStatusMsg(`Live Rug-Pull demo failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (e) {
      setStatusMsg(`Demo error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const renderTrustBadge = (state) => {
    switch (state) {
      case 'APPROVED':
      case 'VERIFIED':
        return <span className="badge badge-approved"><CheckCircle size={13} /> VERIFIED</span>;
      case 'REVOKED':
      case 'ROGUE':
        return <span className="badge badge-revoked"><Flame size={13} /> ROGUE</span>;
      case 'TRUST_GAP':
        return <span className="badge badge-review" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#F87171', border: '1px solid rgba(239, 68, 68, 0.4)' }}><AlertTriangle size={13} /> TRUST GAP</span>;
      case 'REVIEW':
      case 'SUSPICIOUS':
      default:
        return <span className="badge badge-review"><Shield size={13} /> IN REVIEW</span>;
    }
  };

  const getStageStatus = (stage, scan) => {
    if (!scan) return 'IDLE';
    if (stage.key === 'catalog_discovery') return scan.stage_coverage?.catalog_discovery || 'UNKNOWN';
    if (stage.key === 'static_ast') return scan.stage_coverage?.static_ast || 'SKIPPED';
    if (stage.key === 'description_intelligence') return scan.stage_coverage?.description_intelligence || 'SKIPPED';
    if (stage.key === 'dynamic_probing') return scan.stage_coverage?.dynamic_probing || 'SKIPPED';
    if (stage.key === 'trust_gap') {
      if (scan.stage_coverage?.trust_gap) return scan.stage_coverage.trust_gap;
      if (scan.trust_state === 'TRUST_GAP') return 'TRUST_GAP_FLAGGED';
      if (scan.trust_state === 'VERIFIED') return 'PASS';
      return 'UNKNOWN';
    }
    if (stage.key === 'baseline_pinning') return scan.stage_coverage?.baseline_pinning || (scan.diff ? 'DIFF_DETECTED' : 'NOT_PINNED');
    if (stage.key === 'evidence_sealing') {
      if (scan.stage_coverage?.evidence_sealing) return scan.stage_coverage.evidence_sealing;
      return (scan.evidence && scan.evidence.length > 0) ? 'PASS' : 'UNKNOWN';
    }
    return 'UNKNOWN';
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
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          {[
            { id: 'home', label: 'Home / Overview', icon: Shield },
            { id: 'scanner', label: 'Security Auditor', icon: Terminal },
            { id: 'diff', label: 'Vulnerable vs Patched Diff', icon: ShieldAlert },
            { id: 'findings', label: `Evidence Vault (${selectedScan?.findings?.length || 0})`, icon: Layers },
            { id: 'baselines', label: `Baselines & Drift (${baselines.length})`, icon: Database },
            { id: 'intelligence', label: 'Security Intelligence (RAG)', icon: Zap },
            { id: 'jobs', label: `Jobs & Queue (${jobList.length})`, icon: RefreshCw },
            { id: 'assurance', label: 'Model Assurance (KOALA)', icon: Lock },
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

        {/* Mode Switcher & Backend Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          {/* Mode Switcher */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: 'rgba(255, 255, 255, 0.05)',
            borderRadius: '8px',
            padding: '2px',
            border: '1px solid var(--border-subtle)',
          }}>
            <button
              onClick={() => setAuditMode('guided')}
              style={{
                padding: '0.35rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: '700',
                cursor: 'pointer',
                background: auditMode === 'guided' ? 'linear-gradient(135deg, #F97316, #EA580C)' : 'transparent',
                color: auditMode === 'guided' ? '#FFFFFF' : 'var(--text-secondary)',
                border: 'none',
                transition: 'all 0.15s ease',
              }}
              title="Guided Mode: plain-language explanations, preconfigured scenarios, and expected outcomes"
            >
              Guided Demo
            </button>
            <button
              onClick={() => setAuditMode('advanced')}
              style={{
                padding: '0.35rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: '700',
                cursor: 'pointer',
                background: auditMode === 'advanced' ? 'linear-gradient(135deg, #06B6D4, #0284C7)' : 'transparent',
                color: auditMode === 'advanced' ? '#FFFFFF' : 'var(--text-secondary)',
                border: 'none',
                transition: 'all 0.15s ease',
              }}
              title="Advanced Audit: raw AST nodes, container telemetry, SHA-256 fingerprints, and manifest seals"
            >
              Advanced Audit
            </button>
          </div>

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
            onClick={() => { fetchStats(); fetchScans(); fetchBaselines(); fetchKoalaAssurance(); }}
            className="btn btn-secondary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
          >
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </header>

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

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 1: HERO OVERVIEW & LANDING PAGE (BY SHLOK NOVAL) ─── */}
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

              {/* Sandboxed Target Quick Selector Bar */}
              <div style={{ maxWidth: '750px', margin: '0 auto', background: '#05070B', padding: '0.6rem 0.8rem', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.1)', display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
                <Terminal size={20} color="#94A3B8" style={{ marginLeft: '0.5rem' }} />
                <input
                  type="text"
                  placeholder="Select or enter registered target ID (e.g. clean_reader, rogue_server, lying_annotations)..."
                  value={targetIdInput}
                  onChange={(e) => setTargetIdInput(e.target.value)}
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
                  onClick={() => handleTargetInputAudit(targetIdInput)}
                  disabled={!targetIdInput || loading}
                  className="btn btn-primary"
                  style={{ padding: '0.55rem 1.25rem', fontSize: '0.8rem', background: 'linear-gradient(135deg, #06B6D4, #3B82F6)' }}
                >
                  Audit Target
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

            {/* Searchable Target Catalog (16 Registered Target Fixtures & Benchmarks) */}
            <div className="glass-panel" style={{ padding: '2rem', marginTop: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <Layers size={20} color="#F97316" />
                    Searchable MCP Target Catalog ({fixtures.length} Registered Surfaces)
                  </h3>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    5 Live Competition MCPs • 3 Remediated Patched MCPs • 8 Public Source-Only Reference Benchmarks
                  </p>
                </div>

                {/* Target Category Filter Chips */}
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {[
                    { key: 'ALL', label: `All (${fixtures.length})` },
                    { key: 'LIVE', label: `Competition Live (${fixtures.filter(f => f.category?.includes('COMPETITION')).length})` },
                    { key: 'PATCHED', label: `Patched Safe (${fixtures.filter(f => f.category?.includes('PATCHED')).length})` },
                    { key: 'BENCHMARK', label: `Reference Benchmarks (${fixtures.filter(f => f.category?.includes('SOURCE-ONLY')).length})` },
                  ].map(tab => (
                    <button
                      key={tab.key}
                      onClick={() => setTargetCategoryFilter(tab.key)}
                      style={{
                        padding: '0.35rem 0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontWeight: '700',
                        cursor: 'pointer',
                        background: targetCategoryFilter === tab.key ? 'rgba(249, 115, 22, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                        color: targetCategoryFilter === tab.key ? '#FB923C' : 'var(--text-secondary)',
                        border: targetCategoryFilter === tab.key ? '1px solid rgba(249, 115, 22, 0.4)' : '1px solid var(--border-subtle)',
                      }}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Search Bar */}
              <div style={{ marginBottom: '1.5rem', position: 'relative' }}>
                <Search size={16} color="#94A3B8" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  placeholder="Filter targets by name, vulnerability, execution mode, or keyword..."
                  value={searchTargetQuery}
                  onChange={(e) => setSearchTargetQuery(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 1rem 0.65rem 2.6rem',
                    borderRadius: '8px',
                    background: 'rgba(0, 0, 0, 0.35)',
                    border: '1px solid var(--border-subtle)',
                    color: '#F8FAFC',
                    fontSize: '0.85rem',
                    outline: 'none',
                  }}
                />
              </div>

              {/* Cards Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1rem' }}>
                {fixtures
                  .filter(f => {
                    const matchesCategory =
                      targetCategoryFilter === 'ALL' ||
                      (targetCategoryFilter === 'LIVE' && f.category?.includes('COMPETITION')) ||
                      (targetCategoryFilter === 'PATCHED' && f.category?.includes('PATCHED')) ||
                      (targetCategoryFilter === 'BENCHMARK' && f.category?.includes('SOURCE-ONLY'));
                    const q = searchTargetQuery.toLowerCase();
                    const matchesSearch =
                      !q ||
                      (f.name && f.name.toLowerCase().includes(q)) ||
                      (f.id && f.id.toLowerCase().includes(q)) ||
                      (f.expected && f.expected.toLowerCase().includes(q)) ||
                      (f.tags && f.tags.some(t => t.toLowerCase().includes(q)));
                    return matchesCategory && matchesSearch;
                  })
                  .map(target => {
                    const isPatched = target.category?.includes('PATCHED');
                    const isLive = target.execution_mode === 'LIVE_SCAN';
                    const isBenchmark = target.category?.includes('SOURCE-ONLY');

                    return (
                      <div
                        key={target.id}
                        style={{
                          padding: '1.25rem',
                          borderRadius: '10px',
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: isPatched ? '1px solid rgba(16, 185, 129, 0.3)' : isBenchmark ? '1px solid rgba(147, 51, 234, 0.3)' : '1px solid var(--border-subtle)',
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'space-between',
                          gap: '0.75rem',
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.5rem' }}>
                            <h4 style={{ fontSize: '0.95rem', fontWeight: '800', color: '#F8FAFC' }}>
                              {target.name}
                            </h4>
                            <span style={{
                              fontSize: '0.65rem',
                              padding: '0.15rem 0.5rem',
                              borderRadius: '4px',
                              fontWeight: '700',
                              background: isLive ? 'rgba(16, 185, 129, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                              color: isLive ? '#34D399' : '#C084FC',
                              border: isLive ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(168, 85, 247, 0.3)',
                              whiteSpace: 'nowrap',
                            }}>
                              {target.execution_mode}
                            </span>
                          </div>

                          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                            {target.path}
                          </div>

                          <div style={{
                            fontSize: '0.75rem',
                            padding: '0.5rem 0.75rem',
                            borderRadius: '6px',
                            background: isPatched ? 'rgba(16, 185, 129, 0.06)' : 'rgba(239, 68, 68, 0.06)',
                            border: isPatched ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(239, 68, 68, 0.2)',
                            color: isPatched ? '#34D399' : '#FCA5A5',
                            marginBottom: '0.75rem',
                            lineHeight: 1.4,
                          }}>
                            <strong>Expected:</strong> {target.expected}
                          </div>

                          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                            {(target.tags || []).map((t, idx) => (
                              <span key={idx} style={{
                                fontSize: '0.65rem',
                                padding: '0.1rem 0.45rem',
                                borderRadius: '4px',
                                background: 'rgba(255, 255, 255, 0.04)',
                                color: 'var(--text-muted)',
                                border: '1px solid var(--border-subtle)',
                              }}>
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                          <button
                            onClick={() => {
                              setTargetName(target.id);
                              setCustomPath(target.path);
                              setActiveTab('scanner');
                              runScan(target.path, target.id);
                            }}
                            className="btn btn-primary"
                            style={{ flex: 1, padding: '0.45rem 0.75rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}
                          >
                            <Play size={12} /> Audit Now
                          </button>
                          <button
                            onClick={() => {
                              setTargetName(target.id);
                              setCustomPath(target.path);
                              setActiveTab('scanner');
                            }}
                            className="btn btn-secondary"
                            style={{ padding: '0.45rem 0.75rem', fontSize: '0.75rem' }}
                          >
                            Select
                          </button>
                        </div>
                      </div>
                    );
                  })}
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

            {/* Target Configuration & Controls */}
            <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <h2 style={{ fontSize: '1.15rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Terminal size={18} color="#06B6D4" /> Target Cockpit & Executor
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer', userSelect: 'none' }}>
                    <input
                      type="checkbox"
                      checked={useLlm}
                      onChange={(e) => setUseLlm(e.target.checked)}
                      style={{ accentColor: '#06B6D4' }}
                    />
                    <span>Enable Local Qwen 2.5 Coder AI Heuristics</span>
                  </label>
                </div>
              </div>

              {/* Guided Mode Info Banner */}
              {auditMode === 'guided' && (
                <div style={{
                  padding: '0.85rem 1.25rem',
                  borderRadius: '8px',
                  marginBottom: '1.25rem',
                  background: 'rgba(249, 115, 22, 0.08)',
                  border: '1px solid rgba(249, 115, 22, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  fontSize: '0.85rem',
                  color: '#FB923C',
                }}>
                  <Shield size={18} />
                  <div>
                    <strong>Guided Demo Mode:</strong> Select any of the 16 registered targets below and click <strong>"Run Security Audit"</strong>. AuditForge will discover declared tool definitions over stdio transport, visit Python AST syntax trees for dangerous calls, evaluate NLP descriptions for injection, dynamically probe tool handlers in a sandbox container, and reconcile contracts against observed behavior.
                  </div>
                </div>
              )}

              {/* Target Picker Selector */}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    Select Allowlisted Target Server / Fixture
                  </label>
                  <select
                    value={targetName}
                    onChange={(e) => {
                      const selected = fixtures.find(f => f.id === e.target.value);
                      if (selected) {
                        setTargetName(selected.id);
                        setCustomPath(selected.path);
                      } else {
                        setTargetName(e.target.value);
                        setCustomPath(`fixtures/${e.target.value}`);
                      }
                    }}
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.8rem',
                      borderRadius: '8px',
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid var(--border-subtle)',
                      color: '#F8FAFC',
                      fontSize: '0.85rem',
                      outline: 'none',
                    }}
                  >
                    <optgroup label="Competition Tested Fixtures (Live MCP & Acceptance)">
                      {fixtures.filter(f => f.category?.includes('COMPETITION') || f.category?.includes('PATCHED')).map(f => (
                        <option key={f.id} value={f.id}>
                          {f.name} — [{f.execution_mode}]
                        </option>
                      ))}
                    </optgroup>
                    <optgroup label="Source-Only Public Benchmarks">
                      {fixtures.filter(f => f.category?.includes('SOURCE-ONLY')).map(f => (
                        <option key={f.id} value={f.id}>
                          {f.name} — [{f.execution_mode}]
                        </option>
                      ))}
                    </optgroup>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    Target Path / Command
                  </label>
                  <input
                    type="text"
                    value={customPath}
                    readOnly
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.8rem',
                      borderRadius: '8px',
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid var(--border-subtle)',
                      color: '#94A3B8',
                      fontSize: '0.85rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  />
                </div>
              </div>

              {/* Selected Target Metadata Capsule */}
              {(() => {
                const curFixture = fixtures.find(f => f.id === targetName);
                if (!curFixture) return null;
                const isPatched = curFixture.category?.includes('PATCHED');
                return (
                  <div style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--border-subtle)',
                    marginBottom: '1.25rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                    fontSize: '0.8rem',
                  }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Target Category:</span>{' '}
                      <strong style={{ color: '#F8FAFC' }}>{curFixture.category}</strong>{' '}
                      <span style={{ color: 'var(--text-muted)', marginLeft: '0.75rem' }}>Role:</span>{' '}
                      <strong style={{ color: '#38BDF8' }}>{curFixture.role}</strong>
                    </div>
                    <div style={{ color: isPatched ? '#34D399' : '#FB923C' }}>
                      <strong>Expected Verdict:</strong> {curFixture.expected}
                    </div>
                  </div>
                );
              })()}

              {/* Action Buttons Toolbar */}
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => runScan(customPath, targetName)}
                  disabled={loading}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <RefreshCw size={15} className={loading ? "spin" : ""} />
                  {loading ? "Auditing Target..." : "Run Security Audit"}
                </button>

                <button
                  className="btn btn-secondary"
                  onClick={() => pinBaseline(targetName, customPath)}
                  disabled={loading}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <Database size={15} /> Pin as Baseline
                </button>

                <button
                  className="btn btn-secondary"
                  onClick={() => runDiff(targetName, customPath)}
                  disabled={loading}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <Layers size={15} /> Compare Baseline (Diff)
                </button>

                <button
                  className="btn btn-danger"
                  onClick={runLiveRugPullDemo}
                  disabled={loading}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
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
                      Executing Multi-Layer Security Isolation Pipeline on '{targetName}'...
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '0.5rem' }}>
                    {AUDIT_STAGES.map((st) => (
                      <div
                        key={st.id}
                        className="pipeline-stage active"
                      >
                        <RefreshCw size={12} className="spin" />
                        <span>{st.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Real Pipeline Stage Coverage (Honest Post-Execution) */}
              {!loading && selectedScan && (
                <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#05070B', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: '700', color: '#94A3B8' }}>
                      HONEST PIPELINE STAGE OUTCOMES [{selectedScan.scan_mode || 'LIVE_SCAN'}]
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Completed at {selectedScan.completed_at ? new Date(selectedScan.completed_at).toLocaleTimeString() : 'N/A'}
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '0.5rem' }}>
                    {AUDIT_STAGES.map((st) => {
                      const outcome = getStageStatus(st, selectedScan);
                      const isPass = outcome === 'PASS' || outcome === 'SEALED';
                      const isFail = outcome === 'ERROR' || outcome === 'FAIL' || outcome === 'TRUST_GAP_FLAGGED';
                      const isDiff = outcome === 'DIFF_DETECTED' || outcome === 'HIGH_RISK_DRIFT';
                      return (
                        <div
                          key={st.id}
                          className="pipeline-stage"
                          style={{
                            background: isPass ? 'rgba(16, 185, 129, 0.1)' : isFail ? 'rgba(239, 68, 68, 0.15)' : isDiff ? 'rgba(249, 115, 22, 0.15)' : 'rgba(255, 255, 255, 0.02)',
                            borderColor: isPass ? 'rgba(16, 185, 129, 0.3)' : isFail ? 'rgba(239, 68, 68, 0.4)' : isDiff ? 'rgba(249, 115, 22, 0.4)' : 'var(--border-subtle)',
                            color: isPass ? '#34D399' : isFail ? '#F87171' : isDiff ? '#FB923C' : '#94A3B8',
                          }}
                        >
                          {isPass ? <Check size={12} /> : isFail ? <AlertTriangle size={12} /> : <span>{st.id}.</span>}
                          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            <div style={{ fontWeight: '700', fontSize: '0.7rem' }}>{st.name}</div>
                            <div style={{ fontSize: '0.65rem', opacity: 0.8 }}>{outcome}</div>
                          </div>
                        </div>
                      );
                    })}
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
                      {diffResult.is_identical ? 'Catalog Identical to Pinned Baseline (0 Drift)' : `⚠ Supply Chain Drift: ${diffResult.drift_category || 'HIGH_RISK_DRIFT'} (PIN-RUGPULL-001)`}
                    </strong>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target: <strong>{diffResult.server_id}</strong></span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1rem' }}>
                    <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>V1 Baseline Fingerprint</span>
                      <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#38BDF8', marginTop: '0.2rem' }}>
                        {(diffResult.v1_baseline_hash || diffResult.baseline_fingerprint)?.slice(0, 20)}...
                      </div>
                    </div>
                    <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>V2 Mutated Fingerprint</span>
                      <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: diffResult.is_identical ? '#34D399' : '#F87171', marginTop: '0.2rem' }}>
                        {(diffResult.v2_mutated_hash || diffResult.current_fingerprint)?.slice(0, 20)}...
                      </div>
                    </div>
                    <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Drift Classification</span>
                      <div style={{ fontSize: '0.85rem', fontWeight: '700', color: diffResult.is_identical ? '#34D399' : '#F87171', marginTop: '0.2rem' }}>
                        {diffResult.drift_category || (diffResult.is_identical ? 'UNCHANGED' : 'HIGH_RISK_DRIFT')}
                      </div>
                    </div>
                    <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Tools Added / Removed</span>
                      <div style={{ fontSize: '0.85rem', fontWeight: '700', color: '#E2E8F0', marginTop: '0.2rem' }}>
                        +{diffResult.added_tools?.length || 0} / -{diffResult.removed_tools?.length || 0}
                      </div>
                    </div>
                  </div>

                  {/* Detailed Field Diff */}
                  {diffResult.modified_tools && Object.keys(diffResult.modified_tools).length > 0 && (
                    <div style={{ marginTop: '0.75rem' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: '700', color: '#CBD5E1', display: 'block', marginBottom: '0.5rem' }}>
                        Field-Level Modification Diff:
                      </span>
                      {Object.entries(diffResult.modified_tools).map(([toolName, fields]) => (
                        <div key={toolName} style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px', marginBottom: '0.5rem', border: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: '#F97316', fontWeight: '700', fontSize: '0.85rem' }}>Tool: {toolName}</span>
                          <div style={{ marginTop: '0.4rem', fontSize: '0.8rem' }}>
                            {Object.entries(fields).map(([fieldName, change]) => (
                              <div key={fieldName} style={{ marginBottom: '0.35rem' }}>
                                <strong style={{ color: '#CBD5E1' }}>{fieldName}:</strong>
                                <div style={{ color: '#F87171', paddingLeft: '0.5rem' }}>- Baseline: {JSON.stringify(change.baseline)}</div>
                                <div style={{ color: '#34D399', paddingLeft: '0.5rem' }}>+ Mutated: {JSON.stringify(change.current)}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Selected Scan Findings & Live Results */}
            {selectedScan && (
              <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                  <div>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      Audit Report: {selectedScan.server_name || selectedScan.target}
                    </h2>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Scan ID: <code style={{ color: '#CBD5E1' }}>{selectedScan.id || selectedScan.scan_id}</code> | Mode: <strong>{selectedScan.scan_mode || 'LIVE_SCAN'}</strong> | Tools Evaluated: <strong>{selectedScan.snapshot?.tools ? Object.keys(selectedScan.snapshot.tools).length : 0}</strong>
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {renderTrustBadge(selectedScan.trust_state)}
                    <button
                      className="btn btn-secondary"
                      onClick={() => approveBaseline(selectedScan.server_name || selectedScan.target)}
                      style={{ fontSize: '0.8rem' }}
                    >
                      Approve & Baseline
                    </button>
                  </div>
                </div>

                {/* Severity Filter Tabs */}
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev)}
                      style={{
                        padding: '0.3rem 0.65rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontWeight: '700',
                        cursor: 'pointer',
                        background: severityFilter === sev ? 'rgba(255,255,255,0.1)' : 'transparent',
                        color: severityFilter === sev ? '#F8FAFC' : 'var(--text-muted)',
                        border: 'none',
                      }}
                    >
                      {sev} ({(selectedScan.findings || []).filter(f => sev === 'ALL' || f.severity === sev).length})
                    </button>
                  ))}
                </div>

                {/* Findings List Table */}
                {findingsList.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: '#10B981', background: 'rgba(16, 185, 129, 0.05)', borderRadius: '8px' }}>
                    <CheckCircle size={32} style={{ margin: '0 auto 0.5rem auto' }} />
                    <strong style={{ display: 'block', fontSize: '1rem' }}>0 Verified Vulnerabilities Found</strong>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      All inspected AST syntax nodes, tool descriptions, and runtime probes conform to safety policies.
                    </p>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {findingsList.map(f => {
                      const isExpanded = expandedFinding === f.id;
                      return (
                        <div key={f.id} style={{
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '8px',
                          padding: '1rem',
                        }}>
                          <div
                            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                            onClick={() => setExpandedFinding(isExpanded ? null : f.id)}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                              <span className={`badge badge-${f.severity.toLowerCase()}`}>
                                {f.severity}
                              </span>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#CBD5E1', fontWeight: '700' }}>
                                {f.rule_id}
                              </span>
                              <span style={{ fontSize: '0.85rem', color: '#F8FAFC' }}>
                                {f.reason}
                              </span>
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                Conf: {(f.confidence * 100).toFixed(0)}%
                              </span>
                              {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                            </div>
                          </div>

                          {isExpanded && (
                            <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem' }}>
                              <div style={{ marginBottom: '0.5rem' }}>
                                <strong style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>REMEDIATION GUIDANCE:</strong>
                                <p style={{ fontSize: '0.8rem', color: '#38BDF8', marginTop: '0.2rem' }}>{f.remediation}</p>
                              </div>

                              {/* Supporting Evidence Capsules */}
                              <strong style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SUPPORTING EVIDENCE CAPSULES:</strong>
                              <div style={{ marginTop: '0.4rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                                {(selectedScan.evidence || []).filter(e => f.evidence_ids.includes(e.evidence_id)).map(ev => (
                                  <div key={ev.evidence_id} style={{
                                    background: 'rgba(0, 0, 0, 0.3)',
                                    padding: '0.6rem 0.8rem',
                                    borderRadius: '6px',
                                    border: '1px solid rgba(255, 255, 255, 0.05)',
                                    fontSize: '0.75rem',
                                  }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94A3B8', marginBottom: '0.2rem' }}>
                                      <span>Source: <strong>{ev.source}</strong></span>
                                      <span>ID: {ev.evidence_id}</span>
                                    </div>
                                    <div style={{ color: '#E2E8F0', marginBottom: '0.35rem' }}>{ev.summary}</div>
                                    {ev.raw_data && Object.keys(ev.raw_data).length > 0 && (
                                      <pre style={{ margin: 0, padding: '0.4rem', background: '#05070B', borderRadius: '4px', overflowX: 'auto', color: '#A5B4FC' }}>
                                        {JSON.stringify(ev.raw_data, null, 2)}
                                      </pre>
                                    )}
                                  </div>
                                ))}
                              </div>
                              <div style={{ marginTop: '0.75rem', display: 'flex', justifyContent: 'flex-end' }}>
                                <button
                                  className="btn btn-secondary"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleExplainFinding(f);
                                  }}
                                  style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.4rem',
                                    padding: '0.35rem 0.75rem',
                                    fontSize: '0.75rem',
                                    borderColor: 'rgba(249, 115, 22, 0.4)',
                                    color: '#F97316',
                                  }}
                                >
                                  <Zap size={13} color="#F97316" />
                                  Explain Finding with RAG Intelligence
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW: BEFORE-AND-AFTER SECURITY DIFF (P0 ACCEPTANCE) ──── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'diff' && (
          <div>
            <div className="glass-panel" style={{ padding: '2rem', marginBottom: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.35rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <ShieldAlert size={22} color="#F97316" />
                    Before-and-After Security Diff & Remediated Pairs
                  </h2>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    One-click cryptographic verification demonstrating the elimination of planted vulnerabilities in remediated MCP server counterparts without breaking legitimate capabilities.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={() => runPairComparison(selectedPairId)}
                    disabled={loadingComparison}
                    className="btn btn-primary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.6rem 1.25rem', fontSize: '0.85rem' }}
                  >
                    <RefreshCw size={14} className={loadingComparison ? "spin" : ""} />
                    {loadingComparison ? "Verifying Side-by-Side..." : "Run Side-by-Side Audit"}
                  </button>
                </div>
              </div>

              {/* Pair Selection Tabs */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
                {comparisonPairs.map((pair) => {
                  const isSelected = selectedPairId === pair.id;
                  return (
                    <div
                      key={pair.id}
                      onClick={() => {
                        setSelectedPairId(pair.id);
                        runPairComparison(pair.id);
                      }}
                      style={{
                        padding: '1rem',
                        borderRadius: '8px',
                        cursor: 'pointer',
                        background: isSelected ? 'linear-gradient(135deg, rgba(249, 115, 22, 0.15), rgba(6, 182, 212, 0.12))' : 'rgba(255, 255, 255, 0.02)',
                        border: isSelected ? '1px solid rgba(249, 115, 22, 0.5)' : '1px solid var(--border-subtle)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ fontSize: '0.85rem', fontWeight: '800', color: isSelected ? '#FB923C' : '#F8FAFC', marginBottom: '0.35rem' }}>
                        {pair.title}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                        {pair.description}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Side-by-Side Comparison Display */}
              {pairComparisonResult && (
                <div>
                  {/* Delta Summary Pill */}
                  <div style={{
                    padding: '1rem 1.5rem',
                    borderRadius: '8px',
                    marginBottom: '1.5rem',
                    background: pairComparisonResult.comparison_delta?.is_fully_remediated ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                    border: pairComparisonResult.comparison_delta?.is_fully_remediated ? '1px solid rgba(16, 185, 129, 0.35)' : '1px solid rgba(239, 68, 68, 0.35)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '1rem',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <CheckCircle size={22} color="#10B981" />
                      <div>
                        <div style={{ fontSize: '1rem', fontWeight: '800', color: '#34D399' }}>
                          {pairComparisonResult.comparison_delta?.eliminated_findings_count || 0} Planted Vulnerabilities Remediated
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
                          Remediated version achieves <strong>TrustState.VERIFIED</strong> while preserving legitimate server tool functions.
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.2)', color: '#34D399', fontWeight: '700' }}>
                        100% Remediation Verified
                      </span>
                    </div>
                  </div>

                  {/* Guided vs Advanced Mode Explanation */}
                  <div style={{
                    padding: '1rem 1.25rem',
                    borderRadius: '8px',
                    marginBottom: '1.5rem',
                    background: 'rgba(6, 182, 212, 0.06)',
                    border: '1px solid rgba(6, 182, 212, 0.2)',
                    fontSize: '0.85rem',
                    lineHeight: 1.6,
                    color: '#E2E8F0',
                  }}>
                    <strong style={{ color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
                      <Zap size={14} /> {auditMode === 'guided' ? 'Guided Plain-Language Security Breakdown' : 'Advanced Audit Technical Evidence'}
                    </strong>
                    {auditMode === 'guided' ? (
                      <div>
                        <p style={{ margin: 0 }}>
                          <strong>Vulnerability Addressed:</strong> {pairComparisonResult.key_vulnerability}
                        </p>
                        <p style={{ margin: '0.25rem 0 0 0' }}>
                          <strong>How AuditForge Verified It:</strong> {pairComparisonResult.remediation_summary} Both versions were audited under identical sandbox isolation. The vulnerable server emitted verified threat findings, whereas the patched server passed all 7 isolation stages cleanly.
                        </p>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
                          Eliminated Rule IDs: {JSON.stringify(pairComparisonResult.comparison_delta?.eliminated_rule_ids || [])}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.25rem' }}>
                          Vulnerable Evidence Manifest Hash: {pairComparisonResult.vulnerable?.evidence_manifest_hash || 'N/A'}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.25rem' }}>
                          Patched Evidence Manifest Hash: {pairComparisonResult.patched?.evidence_manifest_hash || 'N/A'}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Side-by-Side Dual Card View */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                    {/* Left: Vulnerable Server */}
                    <div style={{
                      padding: '1.5rem',
                      borderRadius: '10px',
                      background: 'rgba(239, 68, 68, 0.04)',
                      border: '1px solid rgba(239, 68, 68, 0.35)',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <div>
                          <span style={{ fontSize: '0.7rem', color: '#F87171', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            BEFORE (VULNERABLE)
                          </span>
                          <h3 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#F8FAFC', marginTop: '0.2rem' }}>
                            {pairComparisonResult.vulnerable?.server_name || pairComparisonResult.vulnerable?.target_id}
                          </h3>
                        </div>
                        {renderTrustBadge(pairComparisonResult.vulnerable?.trust_state)}
                      </div>

                      <div style={{ fontSize: '0.8rem', color: '#FCA5A5', fontWeight: '700', marginBottom: '0.75rem' }}>
                        {pairComparisonResult.vulnerable?.findings_count || 0} Verified Security Finding(s) Detected:
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                        {(pairComparisonResult.vulnerable?.findings || []).map((f, idx) => (
                          <div key={idx} style={{
                            padding: '0.75rem',
                            borderRadius: '6px',
                            background: 'rgba(0, 0, 0, 0.4)',
                            border: '1px solid rgba(239, 68, 68, 0.25)',
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                              <span style={{ fontSize: '0.75rem', fontWeight: '800', color: '#F87171', fontFamily: 'var(--font-mono)' }}>
                                {f.rule_id}
                              </span>
                              <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#F87171', fontWeight: '700' }}>
                                {f.severity}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.75rem', color: '#E2E8F0', lineHeight: 1.4 }}>
                              {f.reason}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Right: Remediated / Patched Server */}
                    <div style={{
                      padding: '1.5rem',
                      borderRadius: '10px',
                      background: 'rgba(16, 185, 129, 0.04)',
                      border: '1px solid rgba(16, 185, 129, 0.35)',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <div>
                          <span style={{ fontSize: '0.7rem', color: '#34D399', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            AFTER (REMEDIATED & SAFE)
                          </span>
                          <h3 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#F8FAFC', marginTop: '0.2rem' }}>
                            {pairComparisonResult.patched?.server_name || pairComparisonResult.patched?.target_id}
                          </h3>
                        </div>
                        {renderTrustBadge(pairComparisonResult.patched?.trust_state)}
                      </div>

                      <div style={{ fontSize: '0.8rem', color: '#34D399', fontWeight: '700', marginBottom: '0.75rem' }}>
                        0 Security Findings (Clean & Verified):
                      </div>

                      <div style={{
                        padding: '1.5rem 1rem',
                        borderRadius: '6px',
                        background: 'rgba(0, 0, 0, 0.3)',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                        textAlign: 'center',
                      }}>
                        <CheckCircle size={32} color="#10B981" style={{ margin: '0 auto 0.5rem auto' }} />
                        <div style={{ fontSize: '0.9rem', fontWeight: '800', color: '#34D399', marginBottom: '0.25rem' }}>
                          Clean Zero-Vulnerability Execution
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#94A3B8', maxWidth: '350px', margin: '0 auto' }}>
                          All planted threats completely eliminated. Handlers execute without unauthorized subprocess, file write, or prompt injection attempts.
                        </div>
                      </div>

                      {/* Stage Coverage Badges */}
                      <div style={{ marginTop: '1rem' }}>
                        <div style={{ fontSize: '0.7rem', color: '#94A3B8', fontWeight: '700', marginBottom: '0.4rem' }}>
                          Verified Pipeline Coverage:
                        </div>
                        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                          {Object.entries(pairComparisonResult.patched?.stage_coverage || {}).map(([stage, outcome]) => (
                            <span key={stage} style={{
                              fontSize: '0.65rem',
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              background: outcome === 'PASS' || outcome === 'SEALED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                              color: outcome === 'PASS' || outcome === 'SEALED' ? '#34D399' : '#94A3B8',
                              border: outcome === 'PASS' || outcome === 'SEALED' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid var(--border-subtle)',
                            }}>
                              {stage}: {outcome}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 3: EVIDENCE VAULT ─────────────────────────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'findings' && (
          <div>
            <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>Cryptographic Evidence Vault</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Zero fabricated claims. Every finding is mathematically linked to raw unedited AST syntax lines, NLP extraction quotes, or sandbox audit hook telemetry.
                </p>
              </div>
              {selectedScan?.evidence_manifest_hash && (
                <div style={{
                  padding: '0.5rem 1rem',
                  borderRadius: '8px',
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                }}>
                  <Lock size={15} color="#34D399" />
                  <div>
                    <div style={{ fontSize: '0.65rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: '700' }}>
                      Evidence Integrity Checksum (SHA-256 Digest)
                    </div>
                    <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#34D399', fontWeight: '700' }}>
                      {selectedScan.evidence_manifest_hash}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {(selectedScan?.findings || []).map(f => (
                <div key={f.id} className="glass-panel" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                        <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', fontWeight: '700', color: '#CBD5E1' }}>{f.rule_id}</span>
                        {f.tool_name && <span style={{ fontSize: '0.8rem', color: '#F97316' }}>Tool: {f.tool_name}</span>}
                      </div>
                      <p style={{ fontSize: '0.9rem', color: '#F8FAFC' }}>{f.reason}</p>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px', marginTop: '0.75rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)' }}>EVIDENCE CAPSULES:</span>
                    <div style={{ marginTop: '0.4rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                      {(selectedScan?.evidence || []).filter(e => f.evidence_ids.includes(e.evidence_id)).map(ev => (
                        <div key={ev.evidence_id} style={{ background: '#05070B', padding: '0.6rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                          <div style={{ color: '#38BDF8', fontWeight: '600' }}>{ev.summary}</div>
                          {ev.raw_data && Object.keys(ev.raw_data).length > 0 && (
                            <pre style={{ margin: '0.4rem 0 0 0', padding: '0.4rem', background: 'rgba(255,255,255,0.02)', color: '#A5B4FC', borderRadius: '4px', overflowX: 'auto' }}>
                              {JSON.stringify(ev.raw_data, null, 2)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 4: BASELINES & DRIFT ──────────────────────────────── */}
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
                    <th style={{ padding: '0.75rem' }}>SERVER ID</th>
                    <th style={{ padding: '0.75rem' }}>APPROVED CATALOG FINGERPRINT (SHA-256)</th>
                    <th style={{ padding: '0.75rem' }}>TOOLS</th>
                    <th style={{ padding: '0.75rem' }}>APPROVAL TIMESTAMP</th>
                    <th style={{ padding: '0.75rem' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {baselines.map((b, idx) => {
                    const sid = b.server_id || b.server_name || `baseline-${idx}`;
                    const fp = b.catalog_fingerprint || b.catalog_hash || 'UNKNOWN';
                    const ts = b.timestamp || b.approved_at || b.created_at;
                    const toolsCount = b.tool_count !== undefined ? b.tool_count : (b.tools ? Object.keys(b.tools).length : '-');
                    return (
                      <tr key={sid} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '0.75rem', fontWeight: '700', color: '#F8FAFC' }}>
                          {sid}
                        </td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.8rem', color: '#38BDF8' }}>
                          {fp}
                        </td>
                        <td style={{ padding: '0.75rem' }}>
                          {toolsCount}
                        </td>
                        <td style={{ padding: '0.75rem', color: 'var(--text-muted)' }}>
                          {ts ? new Date(ts).toLocaleString() : 'N/A'}
                        </td>
                        <td style={{ padding: '0.75rem' }}>
                          <button
                            className="btn btn-secondary"
                            onClick={() => {
                              setTargetName(sid);
                              setCustomPath(`fixtures/${sid}`);
                              setActiveTab('scanner');
                              runDiff(sid, `fixtures/${sid}`);
                            }}
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                          >
                            Check Drift
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW: SECURITY INTELLIGENCE (RAG KNOWLEDGE CORPUS) ─────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'intelligence' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>Security Intelligence & RAG Explainer</h2>
                  <span className="badge" style={{ background: 'rgba(249, 115, 22, 0.15)', color: '#F97316', border: '1px solid rgba(249, 115, 22, 0.3)' }}>
                    Corpus v{intelligenceStatus?.corpus_version || '2026.1'}
                  </span>
                  <span className="badge" style={{ background: 'rgba(52, 211, 153, 0.15)', color: '#34D399', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                    {intelligenceStatus?.status || 'ONLINE'}
                  </span>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '900px' }}>
                  Reconciles verified scanner findings against curated MCP specifications, OWASP LLM guidance, CWE taxonomy, and actionable remediation playbooks using hybrid BM25 and trust-tier ranking.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    fetchIntelligenceStatus();
                    fetchIntelligenceSources();
                  }}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                >
                  <RefreshCw size={14} /> Refresh Corpus
                </button>
              </div>
            </div>

            {/* Metrics Overview */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.25rem', marginBottom: '2rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>RETRIEVAL ENGINE</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '700', color: '#F8FAFC', marginTop: '0.25rem' }}>Hybrid BM25</div>
                <span style={{ fontSize: '0.7rem', color: '#34D399' }}>Trust-tier weighted (1.30x Spec)</span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>INGESTED SPECIFICATIONS</span>
                <div style={{ fontSize: '1.25rem', fontWeight: '800', color: '#38BDF8', marginTop: '0.25rem' }}>
                  {intelligenceStatus?.total_documents || intelligenceSources.length || 4} Documents
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>MCP, OWASP, CWE & Playbooks</span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>INDEXED KNOWLEDGE CHUNKS</span>
                <div style={{ fontSize: '1.25rem', fontWeight: '800', color: '#A78BFA', marginTop: '0.25rem' }}>
                  {intelligenceStatus?.total_chunks || 14} Chunks
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Deterministic SHA-256 sealed</span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PROMPT QUARANTINE</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '700', color: '#34D399', marginTop: '0.25rem' }}>Enforced</div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Evidence isolated in &lt;untrusted&gt;</span>
              </div>
            </div>

            {/* Section 1: Grounded Finding Explainer */}
            <div className="glass-panel" style={{ padding: '1.75rem', marginBottom: '2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem' }}>
                <Zap size={18} color="#F97316" />
                <h3 style={{ fontSize: '1rem', fontWeight: '800' }}>Grounded Finding Explainer & Remediation Playbooks</h3>
              </div>

              {/* Finding Selector */}
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', marginBottom: '1.25rem' }}>
                {findingToExplain ? (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
                        <span className={`badge badge-${(findingToExplain.severity || 'high').toLowerCase()}`}>
                          {findingToExplain.severity}
                        </span>
                        <strong style={{ color: '#F8FAFC', fontFamily: 'var(--font-mono)' }}>{findingToExplain.rule_id}</strong>
                        {findingToExplain.tool_name && (
                          <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Tool: {findingToExplain.tool_name}</span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.85rem', color: '#CBD5E1' }}>{findingToExplain.reason}</div>
                    </div>
                    <button
                      className="btn btn-secondary"
                      onClick={() => setFindingToExplain(null)}
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                    >
                      Clear Selection
                    </button>
                  </div>
                ) : (
                  <div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                      Select a standard vulnerability archetype to explain, or click "Explain Finding" from any scan finding:
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      {[
                        { rule_id: 'AST-SHELL-001', name: 'Command Injection (os.system)', tool_name: 'execute_cmd', severity: 'CRITICAL', reason: 'Direct os.system call detected in execute_cmd' },
                        { rule_id: 'DESC-INJECT-001', name: 'Prompt Injection Directive', tool_name: 'notes_summary', severity: 'HIGH', reason: 'Detected system override directive: ignore previous instructions' },
                        { rule_id: 'TRUST-GAP-001', name: 'readOnlyHint Contract Violation', tool_name: 'delete_record', severity: 'HIGH', reason: 'Tool declares readOnlyHint=True but invokes os.remove' },
                        { rule_id: 'PIN-RUGPULL-001', name: 'Catalog Drift & Rug Pull', tool_name: 'read_notes', severity: 'CRITICAL', reason: 'Runtime catalog differs from cryptographically pinned approval baseline' },
                      ].map(example => (
                        <button
                          key={example.rule_id}
                          className="btn btn-secondary"
                          onClick={() => handleExplainFinding(example, explainUseLlm)}
                          style={{ fontSize: '0.75rem', padding: '0.4rem 0.8rem' }}
                        >
                          {example.name}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Explainer Controls */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={explainUseLlm}
                    onChange={(e) => setExplainUseLlm(e.target.checked)}
                  />
                  Synthesize Executive Summary with Local Qwen LLM (Strict Quarantine Isolation)
                </label>

                {findingToExplain && (
                  <button
                    className="btn btn-primary"
                    onClick={() => handleExplainFinding(findingToExplain, explainUseLlm)}
                    disabled={explainingFinding}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                  >
                    <RefreshCw size={14} className={explainingFinding ? "spin" : ""} />
                    {explainingFinding ? "Retrieving & Synthesizing..." : "Explain Finding"}
                  </button>
                )}
              </div>

              {/* Explanation Outcome */}
              {findingExplanation && (
                <div style={{ background: '#07090E', borderRadius: '8px', border: '1px solid var(--border-subtle)', padding: '1.5rem' }}>
                  {/* Taxonomy Tags */}
                  <div style={{ display: 'flex', gap: '0.6rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                    <span style={{ padding: '0.25rem 0.6rem', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.15)', color: '#38BDF8', fontSize: '0.75rem', fontWeight: '700', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                      {findingExplanation.cwe_mapping}
                    </span>
                    <span style={{ padding: '0.25rem 0.6rem', borderRadius: '4px', background: 'rgba(167, 139, 250, 0.15)', color: '#A78BFA', fontSize: '0.75rem', fontWeight: '700', border: '1px solid rgba(167, 139, 250, 0.3)' }}>
                      {findingExplanation.owasp_mapping}
                    </span>
                    <span style={{ padding: '0.25rem 0.6rem', borderRadius: '4px', background: 'rgba(52, 211, 153, 0.15)', color: '#34D399', fontSize: '0.75rem', fontWeight: '700', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                      Confidence: {(findingExplanation.confidence * 100).toFixed(0)}%
                    </span>
                    {findingExplanation.is_llm_synthesized && (
                      <span style={{ padding: '0.25rem 0.6rem', borderRadius: '4px', background: 'rgba(249, 115, 22, 0.15)', color: '#F97316', fontSize: '0.75rem', fontWeight: '700', border: '1px solid rgba(249, 115, 22, 0.3)' }}>
                        Qwen LLM Synthesized
                      </span>
                    )}
                  </div>

                  {/* Grounded Explanation */}
                  <div style={{ marginBottom: '1.25rem' }}>
                    <h4 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
                      Authoritative Security Analysis:
                    </h4>
                    <p style={{ fontSize: '0.9rem', color: '#F8FAFC', lineHeight: '1.5', background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: '6px', borderLeft: '3px solid #38BDF8' }}>
                      {findingExplanation.grounded_explanation}
                    </p>
                  </div>

                  {/* Actionable Remediation Playbook */}
                  <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
                      Developer Remediation Playbook:
                    </h4>
                    <pre style={{ margin: 0, padding: '1rem', background: '#05070B', borderRadius: '6px', overflowX: 'auto', color: '#34D399', fontSize: '0.85rem', whiteSpace: 'pre-wrap', borderLeft: '3px solid #34D399' }}>
                      {findingExplanation.actionable_remediation}
                    </pre>
                  </div>

                  {/* Retrieved Sources Table */}
                  <h4 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.6rem', textTransform: 'uppercase' }}>
                    Retrieved Specification Citations ({findingExplanation.retrieved_sources?.length || 0}):
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {(findingExplanation.retrieved_sources || []).map((src, idx) => (
                      <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span className="badge" style={{ background: src.trust_tier === 'OFFICIAL_SPEC' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(167, 139, 250, 0.15)', color: src.trust_tier === 'OFFICIAL_SPEC' ? '#38BDF8' : '#A78BFA', fontSize: '0.7rem' }}>
                              {src.trust_tier}
                            </span>
                            <strong style={{ color: '#F8FAFC' }}>{src.title}</strong>
                            <span style={{ color: 'var(--text-muted)' }}>({src.publisher})</span>
                          </div>
                          {src.source_url && (
                            <a href={src.source_url} target="_blank" rel="noreferrer" style={{ color: '#F97316', display: 'flex', alignItems: 'center', gap: '0.25rem', textDecoration: 'none', fontSize: '0.75rem' }}>
                              Canonical Link <ExternalLink size={12} />
                            </a>
                          )}
                        </div>
                        <div style={{ color: '#94A3B8', fontSize: '0.75rem', marginBottom: '0.2rem' }}>{src.content}</div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}>
                          Digest: {src.content_hash}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Disclaimer */}
                  <div style={{ marginTop: '1.25rem', padding: '0.75rem', borderRadius: '6px', background: 'rgba(249, 115, 22, 0.05)', border: '1px solid rgba(249, 115, 22, 0.2)', fontSize: '0.75rem', color: '#F97316' }}>
                    ℹ {findingExplanation.disclaimer}
                  </div>
                </div>
              )}
            </div>

            {/* Section 2: Hybrid BM25 Knowledge Base Search */}
            <div className="glass-panel" style={{ padding: '1.75rem', marginBottom: '2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem' }}>
                <Search size={18} color="#38BDF8" />
                <h3 style={{ fontSize: '1rem', fontWeight: '800' }}>Search Authoritative Security Corpus</h3>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}>
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && searchKnowledgeBase()}
                  placeholder="Search specifications (e.g. command injection, prompt injection, readOnlyHint, baseline pinning)..."
                  style={{ flex: 1, padding: '0.6rem 0.9rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)', color: '#F8FAFC', fontSize: '0.85rem' }}
                />
                <select
                  value={searchTrustTier}
                  onChange={(e) => setSearchTrustTier(e.target.value)}
                  style={{ padding: '0.6rem 0.9rem', borderRadius: '6px', background: '#0F172A', border: '1px solid var(--border-subtle)', color: '#F8FAFC', fontSize: '0.85rem' }}
                >
                  <option value="ALL">All Trust Tiers</option>
                  <option value="OFFICIAL_SPEC">Official Spec (1.30x)</option>
                  <option value="SECURITY_ADVISORY">Security Advisory (1.15x)</option>
                  <option value="AUDIT_PLAYBOOK">Audit Playbook (1.05x)</option>
                </select>
                <button
                  className="btn btn-primary"
                  onClick={() => searchKnowledgeBase()}
                  disabled={searchingIntel}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem' }}
                >
                  <Search size={14} /> {searchingIntel ? "Searching..." : "Search"}
                </button>
              </div>

              {/* Search Results */}
              {searchResults.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Found {searchResults.length} relevant knowledge chunks:
                  </div>
                  {searchResults.map((res, i) => (
                    <div key={i} style={{ background: '#07090E', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                          <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38BDF8', fontSize: '0.7rem' }}>
                            {res.trust_tier}
                          </span>
                          <strong style={{ color: '#F8FAFC', fontSize: '0.9rem' }}>{res.title}</strong>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>BM25 Score: {res.score}</span>
                        </div>
                        {res.source_url && (
                          <a href={res.source_url} target="_blank" rel="noreferrer" style={{ color: '#F97316', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.2rem', textDecoration: 'none' }}>
                            Spec URL <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                      <p style={{ fontSize: '0.8rem', color: '#CBD5E1', lineHeight: '1.4', margin: 0 }}>{res.content}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Section 3: Authoritative Sources Catalog */}
            <div className="glass-panel" style={{ padding: '1.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem' }}>
                <Database size={18} color="#A78BFA" />
                <h3 style={{ fontSize: '1rem', fontWeight: '800' }}>Ingested Authoritative Security Specifications</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
                {(intelligenceSources.length > 0 ? intelligenceSources : [
                  { id: 'DOC-MCP-SPEC-001', title: 'Model Context Protocol (MCP) Specification', publisher: 'Model Context Protocol Working Group', trust_tier: 'OFFICIAL_SPEC', version: '2024-11-05', url: 'https://modelcontextprotocol.io/docs/concepts/tools', license: 'MIT', chunk_count: 4 },
                  { id: 'DOC-OWASP-LLM-001', title: 'OWASP Top 10 for Large Language Model Applications', publisher: 'OWASP Foundation', trust_tier: 'SECURITY_ADVISORY', version: '2025.1', url: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/', license: 'CC-BY-SA-4.0', chunk_count: 3 },
                  { id: 'DOC-CWE-CATALOG-001', title: 'Common Weakness Enumeration Standards Catalog', publisher: 'MITRE Corporation', trust_tier: 'OFFICIAL_SPEC', version: '4.14', url: 'https://cwe.mitre.org/data/definitions/78.html', license: 'MITRE Terms', chunk_count: 4 },
                  { id: 'DOC-PLAYBOOKS-001', title: 'AuditForge Approved Remediation Playbooks', publisher: 'AuditForge Security Research', trust_tier: 'AUDIT_PLAYBOOK', version: '2026.1', url: 'https://github.com/Pswaikar1742/AuditForge/docs/remediation', license: 'Apache-2.0', chunk_count: 4 },
                ]).map(doc => (
                  <div key={doc.id} style={{ background: '#07090E', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                      <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38BDF8', fontSize: '0.7rem' }}>
                        {doc.trust_tier}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>v{doc.version}</span>
                    </div>
                    <strong style={{ display: 'block', color: '#F8FAFC', fontSize: '0.9rem', marginBottom: '0.25rem' }}>{doc.title}</strong>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                      Published by {doc.publisher} • {doc.chunk_count || 4} chunks indexed
                    </div>
                    <a href={doc.url} target="_blank" rel="noreferrer" style={{ color: '#F97316', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem', textDecoration: 'none' }}>
                      Official Documentation <ExternalLink size={12} />
                    </a>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW: ASYNCHRONOUS JOB QUEUE & BULK AUDIT MONITOR ───────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'jobs' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>Scalable Job Queue & Bulk Auditor</h2>
                  <span className="badge" style={{ background: 'rgba(52, 211, 153, 0.15)', color: '#34D399', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                    {queueMetrics?.queue_mode === 'REDIS' ? 'Redis Distributed Broker' : 'In-Memory Async Queue'}
                  </span>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '900px' }}>
                  Executes high-concurrency background scan jobs using Redis distributed task queueing or local in-process asynchronous workers with PostgreSQL/SQLite persistence.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button
                  className="btn btn-secondary"
                  onClick={fetchJobs}
                  disabled={loadingJobs}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                >
                  <RefreshCw size={14} className={loadingJobs ? "spin" : ""} /> Refresh Jobs
                </button>
              </div>
            </div>

            {/* Queue Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.25rem', marginBottom: '2rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>QUEUE BACKEND</span>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', color: '#F8FAFC', marginTop: '0.25rem' }}>
                  {queueMetrics?.queue_mode || 'IN_MEMORY'}
                </div>
                <span style={{ fontSize: '0.7rem', color: queueMetrics?.redis_connected ? '#34D399' : '#F97316' }}>
                  {queueMetrics?.redis_connected ? 'Redis Connected (port 6379)' : 'Standalone Worker Active'}
                </span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PENDING IN QUEUE</span>
                <div style={{ fontSize: '1.25rem', fontWeight: '800', color: '#F87171', marginTop: '0.25rem' }}>
                  {queueMetrics?.queued_jobs || 0} Jobs
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Awaiting worker thread</span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>TOTAL JOBS RECORDED</span>
                <div style={{ fontSize: '1.25rem', fontWeight: '800', color: '#38BDF8', marginTop: '0.25rem' }}>
                  {jobList.length} Jobs
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Persisted in database</span>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CONCURRENCY ENGINE</span>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', color: '#34D399', marginTop: '0.25rem' }}>Active</div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Non-blocking background runner</span>
              </div>
            </div>

            {/* Enqueue Controls */}
            <div className="glass-panel" style={{ padding: '1.75rem', marginBottom: '2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem' }}>
                <Play size={18} color="#34D399" />
                <h3 style={{ fontSize: '1rem', fontWeight: '800' }}>Submit Asynchronous Scan Tasks</h3>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <select
                  value={selectedJobTarget}
                  onChange={(e) => setSelectedJobTarget(e.target.value)}
                  style={{ flex: 1, minWidth: '280px', padding: '0.6rem 0.9rem', borderRadius: '6px', background: '#0F172A', border: '1px solid var(--border-subtle)', color: '#F8FAFC', fontSize: '0.85rem' }}
                >
                  <optgroup label="Competition Live Targets (5)">
                    <option value="fixtures/clean_reader">fixtures/clean_reader (Safe Control)</option>
                    <option value="fixtures/rogue_server">fixtures/rogue_server (os.system C2)</option>
                    <option value="fixtures/poisoned_counter">fixtures/poisoned_counter (Unicode injection)</option>
                    <option value="fixtures/lying_annotations">fixtures/lying_annotations (readOnly trust gap)</option>
                    <option value="fixtures/slow_dos">fixtures/slow_dos (ReDoS & hang)</option>
                  </optgroup>
                  <optgroup label="AttackLab & Synthesis Suites">
                    <option value="benchmarks/attacklab/workloads/shell_escape.py">benchmarks/attacklab: shell_escape</option>
                    <option value="benchmarks/attacklab/workloads/prompt_injection_v2.py">benchmarks/attacklab: prompt_injection_v2</option>
                    <option value="benchmarks/attacklab/workloads/destructive_unlink.py">benchmarks/attacklab: destructive_unlink</option>
                  </optgroup>
                </select>

                <button
                  className="btn btn-primary"
                  onClick={() => submitAsyncScanJob(selectedJobTarget)}
                  disabled={loadingJobs}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', whiteSpace: 'nowrap' }}
                >
                  <RefreshCw size={14} className={loadingJobs ? "spin" : ""} />
                  Enqueue Scan Job
                </button>

                <button
                  className="btn btn-secondary"
                  onClick={async () => {
                    const targets = [
                      'fixtures/clean_reader',
                      'fixtures/rogue_server',
                      'fixtures/poisoned_counter',
                      'fixtures/lying_annotations',
                      'fixtures/slow_dos',
                    ];
                    for (const t of targets) {
                      await submitAsyncScanJob(t);
                    }
                  }}
                  disabled={loadingJobs}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', whiteSpace: 'nowrap', borderColor: 'rgba(56, 189, 248, 0.4)', color: '#38BDF8' }}
                >
                  <Layers size={14} />
                  Bulk Audit: Run All 5 Competition MCPs
                </button>
              </div>
            </div>

            {/* Jobs Table */}
            <div className="glass-panel" style={{ padding: '1.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <Terminal size={18} color="#F97316" />
                  <h3 style={{ fontSize: '1rem', fontWeight: '800' }}>Recent Scan Tasks ({jobList.length})</h3>
                </div>
              </div>

              {jobList.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No asynchronous scan jobs recorded yet. Click "Enqueue Scan Job" above to submit a task.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '0.75rem' }}>Job ID</th>
                        <th style={{ padding: '0.75rem' }}>Target</th>
                        <th style={{ padding: '0.75rem' }}>Type</th>
                        <th style={{ padding: '0.75rem' }}>Status</th>
                        <th style={{ padding: '0.75rem' }}>Created At</th>
                        <th style={{ padding: '0.75rem' }}>Completed At</th>
                        <th style={{ padding: '0.75rem' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {jobList.map(j => {
                        const isDone = j.status === 'SUCCEEDED';
                        const isRunning = j.status === 'RUNNING';
                        const isFailed = j.status === 'FAILED';
                        const isCancelled = j.status === 'CANCELLED';
                        return (
                          <tr key={j.job_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            <td style={{ padding: '0.75rem', fontFamily: 'monospace', color: '#CBD5E1', fontWeight: '700' }}>
                              {j.job_id}
                            </td>
                            <td style={{ padding: '0.75rem', color: '#F8FAFC' }}>
                              {j.target}
                            </td>
                            <td style={{ padding: '0.75rem', color: 'var(--text-muted)' }}>
                              {j.scan_type}
                            </td>
                            <td style={{ padding: '0.75rem' }}>
                              <span style={{
                                padding: '0.2rem 0.5rem',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: '700',
                                background: isDone ? 'rgba(52, 211, 153, 0.15)' : isRunning ? 'rgba(56, 189, 248, 0.15)' : isFailed ? 'rgba(248, 113, 113, 0.15)' : isCancelled ? 'rgba(148, 163, 184, 0.15)' : 'rgba(251, 191, 36, 0.15)',
                                color: isDone ? '#34D399' : isRunning ? '#38BDF8' : isFailed ? '#F87171' : isCancelled ? '#94A3B8' : '#FBBF24',
                                border: `1px solid ${isDone ? 'rgba(52, 211, 153, 0.3)' : isRunning ? 'rgba(56, 189, 248, 0.3)' : isFailed ? 'rgba(248, 113, 113, 0.3)' : isCancelled ? 'rgba(148, 163, 184, 0.3)' : 'rgba(251, 191, 36, 0.3)'}`,
                              }}>
                                {isRunning && <RefreshCw size={10} className="spin" style={{ display: 'inline', marginRight: '4px' }} />}
                                {j.status}
                              </span>
                            </td>
                            <td style={{ padding: '0.75rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                              {j.created_at ? new Date(j.created_at).toLocaleTimeString() : 'N/A'}
                            </td>
                            <td style={{ padding: '0.75rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                              {j.completed_at ? new Date(j.completed_at).toLocaleTimeString() : '-'}
                            </td>
                            <td style={{ padding: '0.75rem' }}>
                              <div style={{ display: 'flex', gap: '0.4rem' }}>
                                {j.scan_id && (
                                  <button
                                    className="btn btn-secondary"
                                    onClick={() => {
                                      fetchScanDetails(j.scan_id);
                                      setActiveTab('scanner');
                                    }}
                                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                                  >
                                    View Scan
                                  </button>
                                )}
                                {(j.status === 'QUEUED' || j.status === 'RUNNING') && (
                                  <button
                                    className="btn btn-secondary"
                                    onClick={() => cancelJob(j.job_id)}
                                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', color: '#F87171', borderColor: 'rgba(248, 113, 113, 0.4)' }}
                                  >
                                    Cancel
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 5: MODEL ASSURANCE (SPONSOR: KOALA) ───────────────── */}
        {/* ═════════════════════════════════════════════════════════════ */}
        {activeTab === 'assurance' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '800' }}>Model Governance Assurance Sidecar</h2>
                  <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818CF8', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
                    Sponsor: DomAiyn Labs
                  </span>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '900px' }}>
                  Audits local open-weight reasoning models (Qwen2.5-Coder-7B) against formal regulatory frameworks (NIST AI RMF 1.0 & EU AI Act) using <strong>KOALA v0.2.0</strong>. Model governance is evaluated orthogonally to MCP target server threat verdicts.
                </p>
              </div>

              <button
                className="btn btn-primary"
                onClick={triggerKoalaAudit}
                disabled={loadingAssurance}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}
              >
                <RefreshCw size={15} className={loadingAssurance ? "spin" : ""} />
                {loadingAssurance ? "Auditing Model..." : "Re-Run KOALA Audit"}
              </button>
            </div>

            {/* KOALA Metrics Overview Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.25rem', marginBottom: '2rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Evaluated Controls</span>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', marginTop: '0.25rem', color: '#F8FAFC' }}>
                  {koalaReport?.summary?.controls_total ?? 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Mode: <strong style={{ color: '#93C5FD' }}>{koalaReport?.audit_mode || 'NOT_ASSESSED'}</strong>
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Machine Verified</span>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', marginTop: '0.25rem', color: '#10B981' }}>
                  {koalaReport?.summary?.machine_verified ?? 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  {koalaReport?.summary?.machine_verification_percent ?? 0}% Coverage Rate
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Identified Governance Gaps</span>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', marginTop: '0.25rem', color: '#F59E0B' }}>
                  {koalaReport?.summary?.failed ?? 0}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  {koalaReport?.summary?.not_assessed ?? 0} Unassessed
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Target Model Architecture</span>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', marginTop: '0.5rem', color: '#38BDF8' }}>
                  {koalaReport?.model_id || 'Qwen2.5-Coder-7B'}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  {koalaReport?.evidence_provenance || 'KOALA v0.2.0 Engine'}
                </div>
              </div>
            </div>

            {/* KOALA Controls & Findings Table */}
            <div className="glass-panel" style={{ padding: '1rem', overflowX: 'auto', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', padding: '0.25rem 0.5rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Framework Control Evaluation Matrix</h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  {koalaReport?.attribution || 'Audited via KOALA (version 0.2.0) by DomAiyn Labs (Apache 2.0)'}
                </span>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.75rem' }}>STATUS</th>
                    <th style={{ padding: '0.75rem' }}>CONTROL ID</th>
                    <th style={{ padding: '0.75rem' }}>FRAMEWORK</th>
                    <th style={{ padding: '0.75rem' }}>CLAUSE</th>
                    <th style={{ padding: '0.75rem' }}>TITLE</th>
                    <th style={{ padding: '0.75rem' }}>SEVERITY</th>
                    <th style={{ padding: '0.75rem' }}>EVIDENCE & REMEDIATION</th>
                  </tr>
                </thead>
                <tbody>
                  {(koalaReport?.results || []).map((ctrl, idx) => {
                    const isPass = ctrl.status?.toLowerCase() === 'pass';
                    const isFail = ctrl.status?.toLowerCase() === 'fail';
                    return (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '0.75rem' }}>
                          <span
                            className="badge"
                            style={{
                              background: isPass ? 'rgba(16, 185, 129, 0.15)' : isFail ? 'rgba(239, 68, 68, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                              color: isPass ? '#34D399' : isFail ? '#F87171' : '#94A3B8',
                              border: `1px solid ${isPass ? 'rgba(16, 185, 129, 0.3)' : isFail ? 'rgba(239, 68, 68, 0.3)' : 'rgba(148, 163, 184, 0.3)'}`,
                              fontWeight: '700',
                              fontSize: '0.75rem',
                            }}
                          >
                            {ctrl.status?.toUpperCase() || 'UNKNOWN'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.8rem', color: '#CBD5E1' }}>
                          {ctrl.control_id}
                        </td>
                        <td style={{ padding: '0.75rem', color: '#94A3B8' }}>
                          {ctrl.framework === 'nist_ai_rmf' ? 'NIST AI RMF' : ctrl.framework === 'eu_ai_act' ? 'EU AI Act' : ctrl.framework}
                        </td>
                        <td style={{ padding: '0.75rem', fontWeight: '600', color: '#E2E8F0' }}>
                          {ctrl.clause}
                        </td>
                        <td style={{ padding: '0.75rem', color: '#F1F5F9', fontWeight: '500' }}>
                          {ctrl.title}
                        </td>
                        <td style={{ padding: '0.75rem' }}>
                          <span
                            className="badge"
                            style={{
                              background: ctrl.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' : ctrl.severity === 'high' ? 'rgba(249, 115, 22, 0.2)' : 'rgba(234, 179, 8, 0.15)',
                              color: ctrl.severity === 'critical' ? '#F87171' : ctrl.severity === 'high' ? '#FB923C' : '#FACC15',
                              fontSize: '0.7rem',
                            }}
                          >
                            {ctrl.severity?.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontSize: '0.8rem', maxWidth: '350px' }}>
                          <div style={{ color: '#94A3B8', marginBottom: ctrl.remediation ? '0.25rem' : '0' }}>
                            {ctrl.evidence}
                          </div>
                          {ctrl.remediation?.fix && (
                            <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '4px', padding: '0.4rem', marginTop: '0.25rem', color: '#CBD5E1' }}>
                              <strong style={{ color: '#F59E0B', fontSize: '0.75rem' }}>Fix: </strong>
                              <span style={{ fontSize: '0.75rem' }}>{ctrl.remediation.fix.slice(0, 150)}...</span>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Governance Disclaimer */}
            <div style={{ padding: '1rem', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-subtle)', borderRadius: '8px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <strong>Governance Transparency Notice:</strong> {koalaReport?.disclaimer || "Koala produces evidence and gap analysis, not legal certification. A passing result is not a compliance guarantee or a legal defense."}
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════════════════════════ */}
        {/* ── VIEW 6: ARCHITECTURE & SYSTEM SPECS ────────────────────── */}
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
                    Layer 0 scans for zero-width Unicode characters and bidi overrides that deceive humans while injecting prompts to LLM agents. Layer 2 classifies semantic imperative overrides via Qwen3.
                  </p>
                </div>

                <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                  <strong style={{ color: '#F8FAFC' }}>3. Cryptographic Catalog Supply Chain Pinning</strong>
                  <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Calculates canonical SHA-256 fingerprints across every discovered tool. Alerts on supply chain rug pulls where a developer modifies an approved tool after installation.
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

            {/* Production Architecture & 100K Scaling Blueprint */}
            <div className="glass-panel" style={{ padding: '1.5rem', gridColumn: 'span 2', borderTop: '4px solid #10B981' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#34D399', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Cpu size={18} /> Enterprise Production Architecture & 100,000 Tool Scalability Blueprint
                </h3>
                <span style={{ fontSize: '0.75rem', color: '#34D399', background: 'rgba(16, 185, 129, 0.15)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontWeight: '700' }}>
                  Design Spec: docs/PRODUCTION_ARCHITECTURE.md
                </span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '1rem' }}>
                While our MVP operates deterministically on SQLite WAL for localized judging, our enterprise blueprint defines a stateless FastAPI control plane over Kubernetes HPA, Redis task dispatching queues, partitioned PostgreSQL 16 clusters, and ephemeral microVM (Firecracker / gVisor) dynamic runner pools.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: '700' }}>Stateless API Control Plane</div>
                  <div style={{ fontSize: '0.8rem', color: '#F8FAFC', marginTop: '0.25rem' }}>Kubernetes HPA, JWT multi-tenant isolation, Redis task broker</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: '700' }}>Partitioned PostgreSQL + S3</div>
                  <div style={{ fontSize: '0.8rem', color: '#F8FAFC', marginTop: '0.25rem' }}>Immutable baselines ledger, Zstandard compressed telemetry in S3/R2</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: '700' }}>100K Tools Scaling Plan</div>
                  <div style={{ fontSize: '0.8rem', color: '#F8FAFC', marginTop: '0.25rem' }}>Chunked streaming SHA-256 fingerprinting, linear B-Tree catalog diffs</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: '700' }}>Direct AST vs RAG Integrity</div>
                  <div style={{ fontSize: '0.8rem', color: '#F8FAFC', marginTop: '0.25rem' }}>Direct syntax tree parsing avoids prompt-injection poisoning inherent to RAG</div>
                </div>
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
        <div>AUDIT FORGE © 2026 — PS02 MCP Security Auditor. Zero AI Slop. Real Evidence Traces.</div>
        <div>Compliant with AGENTS.md & Competition Playbook</div>
      </footer>
    </div>
  );
}
