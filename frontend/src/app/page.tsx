'use client';

// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// you may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This code is for PoC environment only.
// This demo code is not built for production workload.

import React, { useState, useEffect, useRef } from 'react';
import Editor from '@monaco-editor/react';
import { Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader, Check, X, Code, MessageSquare, Paperclip, BarChart, Database, Cpu, DollarSign, Calendar, Filter, Zap, Layers, Server, CheckSquare, RefreshCw, Activity } from 'lucide-react';

// Helper functions for UTC date formatting (YYYY-MM-DD)
const formatDateUTC = (d: Date): string => {
  return d.toISOString().split('T')[0];
};

const getTodayUTC = (): string => {
  return formatDateUTC(new Date());
};

const getYesterdayUTC = (): string => {
  const d = new Date();
  d.setDate(d.getDate() - 1);
  return formatDateUTC(d);
};

const getDaysAgoUTC = (days: number): string => {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return formatDateUTC(d);
};

export default function Home() {
  const [activeTab, setActiveTab] = useState<'gitops' | 'sandbox' | 'analytics' | 'fleet'>('gitops');
  
  // Sandbox state
  const [code, setCode] = useState<string>(
    "// Write or paste your vulnerable route code here...\n" +
    "const express = require('express');\n" +
    "const router = express.Router();\n" +
    "const db = require('../models');\n\n" +
    "router.get('/search', async (req, res) => {\n" +
    "  const query = req.query.q;\n" +
    "  // Vulnerable Query\n" +
    "  const results = await db.sequelize.query(\n" +
    "    `SELECT * FROM Products WHERE name LIKE '%${query}%'`\n" +
    "  );\n" +
    "  res.json(results);\n" +
    "});\n\n" +
    "module.exports = router;"
  );
  
  const [intent, setIntent] = useState<string>('Fix the SQL injection vulnerability in the search route.');
  const [sessionId, setSessionId] = useState<string>('');
  const [logs, setLogs] = useState<{ timestamp: string; type: string; message: string }[]>([]);
  const [qaReport, setQaReport] = useState<{ matches_intent: boolean; feedback: string } | null>(null);
  const [semanticReport, setSemanticReport] = useState<{ has_secrets: boolean; hygiene_issues: string[] } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  

  // Fleet & Monorepo Scaling State
  const [fleetScopeType, setFleetScopeType] = useState<'EXPLICIT_LIST' | 'ORGANIZATION' | 'TOPIC_FILTER'>('EXPLICIT_LIST');
  const [fleetTargetRepo, setFleetTargetRepo] = useState<string>('your-org/your-repo');
  const [fleetOrg, setFleetOrg] = useState<string>('your-org');
  const [fleetTopics, setFleetTopics] = useState<string>('security,production');
  const [monorepoLocThreshold, setMonorepoLocThreshold] = useState<number>(10000);
  const [fleetModelTier, setFleetModelTier] = useState<string>('gemini-3.8-flash');
  const [fleetPreviewPlan, setFleetPreviewPlan] = useState<any>(null);
  const [loadingFleetPreview, setLoadingFleetPreview] = useState<boolean>(false);
  const [fleetScans, setFleetScans] = useState<any[]>([]);
  const [loadingFleetScans, setLoadingFleetScans] = useState<boolean>(false);
  const [repoSummary, setRepoSummary] = useState<any>(null);
  const [loadingRepoSummary, setLoadingRepoSummary] = useState<boolean>(false);
  const [syncingMasterIssue, setSyncingMasterIssue] = useState<boolean>(false);
  const [selectedFleetScanId, setSelectedFleetScanId] = useState<string | null>(null);

  // Dashboard state
  const [patches, setPatches] = useState<any[]>([]);
  const [loadingPatches, setLoadingPatches] = useState<boolean>(false);
  const [scans, setScans] = useState<any[]>([]);
  const [loadingScans, setLoadingScans] = useState<boolean>(false);

  // Analytics state
  const [analytics, setAnalytics] = useState<any>(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState<boolean>(false);
  const [dateFilterMode, setDateFilterMode] = useState<'today' | 'yesterday' | '7d' | '30d' | 'custom'>('7d');
  const [startDate, setStartDate] = useState<string>(getDaysAgoUTC(7));
  const [endDate, setEndDate] = useState<string>(getTodayUTC());

  // Remediation & Multi-Repo Analytics state
  const [remediationData, setRemediationData] = useState<any>(null);
  const [loadingRemediation, setLoadingRemediation] = useState<boolean>(false);
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [availableRepos, setAvailableRepos] = useState<string[]>([]);

  // Dismissal / Risk acceptance modal state
  const [dismissModalOpen, setDismissModalOpen] = useState<boolean>(false);
  const [dismissCommitSha, setDismissCommitSha] = useState<string>('');
  const [dismissFinding, setDismissFinding] = useState<any>(null);
  const [dismissCategory, setDismissCategory] = useState<string>('FALSE_POSITIVE');
  const [dismissReason, setDismissReason] = useState<string>('');
  const [submittingDismissal, setSubmittingDismissal] = useState<boolean>(false);

  // Scan details tracking
  const [expandedTimelines, setExpandedTimelines] = useState<Record<string, boolean>>({});
  const [expandedConsoles, setExpandedConsoles] = useState<Record<string, boolean>>({});
  const [activeLogTabs, setActiveLogTabs] = useState<Record<string, 'find' | 'verify' | 'fix'>>({});

  const toggleTimeline = (sha: string) => {
    setExpandedTimelines(prev => ({ ...prev, [sha]: !prev[sha] }));
  };

  const toggleConsole = (sha: string) => {
    setExpandedConsoles(prev => ({ ...prev, [sha]: !prev[sha] }));
  };

  const selectLogTab = (sha: string, tab: 'find' | 'verify' | 'fix') => {
    setActiveLogTabs(prev => ({ ...prev, [sha]: tab }));
  };

  const handleInspectScanPatch = (prNumber: number) => {
    const patch = patches.find(p => p.pr_number === prNumber);
    if (patch) {
      setFilename(patch.filename);
      setGitDiff(patch.git_diff);
      setPatchedCode(patch.patched_code);
      setInspectionTab('diff');
      setShowInspectionModal(true);
    } else {
      alert(`Proposed patch for PR #${prNumber} not loaded yet. Please wait or retry.`);
    }
  };

  // Inspection Modal state
  const [showInspectionModal, setShowInspectionModal] = useState<boolean>(false);
  const [inspectionTab, setInspectionTab] = useState<'diff' | 'code'>('diff');
  const [filename, setFilename] = useState<string>('');
  const [patchedCode, setPatchedCode] = useState<string>('');
  const [gitDiff, setGitDiff] = useState<string>('');
  
  // HITL Approval state (for Sandbox WS mode)
  const [showApprovalModal, setShowApprovalModal] = useState<boolean>(false);
  const [sandboxFilename, setSandboxFilename] = useState<string>('');
  const [sandboxOriginalCode, setSandboxOriginalCode] = useState<string>('');
  const [sandboxPatchedCode, setSandboxPatchedCode] = useState<string>('');

  const wsRef = useRef<WebSocket | null>(null);
  const logContainerRef = useRef<HTMLDivElement | null>(null);

  const getApiUrl = (path: string) => {
    if (typeof window !== 'undefined') {
      const origin = window.location.origin;
      if (origin.includes(':3000')) {
        return `http://localhost:8000${path}`;
      }
      return `${origin}${path}`;
    }
    return `http://localhost:8000${path}`;
  };

  const getWsUrl = () => {
    if (typeof window !== 'undefined') {
      const origin = window.location.origin;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      if (origin.includes(':3000')) {
        return `ws://localhost:8000/ws/${sessionId}`;
      }
      const host = window.location.host;
      return `${protocol}//${host}/ws/${sessionId}`;
    }
    return `ws://localhost:8000/ws/${sessionId}`;
  };

  // Generate unique session ID on start
  useEffect(() => {
    const randomUuid = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    setSessionId(randomUuid);
  }, []);

  // Connect to WebSocket when sessionId changes (for Sandbox WS mode)
  useEffect(() => {
    if (!sessionId) return;

    const wsUrl = getWsUrl();
    addLog('system', `Connecting to WebSocket: ${wsUrl}...`);
    
    const ws = new WebSocket(wsUrl);

    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      addLog('system', 'Connected to WebSocket server.');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WS Message received:', data);

        if (data.type === 'status') {
          addLog('info', data.message);
        } else if (data.type === 'error') {
          addLog('error', data.message);
          setLoading(false);
        } else if (data.type === 'pre_check_results') {
          addLog('success', 'Pre-check agents finished execution.');
          setQaReport(data.qa_report);
          setSemanticReport(data.semantic_report);
          setLoading(false);
        } else if (data.type === 'APPROVAL_REQUIRED') {
          addLog('warning', 'Human-In-The-Loop (HITL) approval required.');
          setSandboxFilename(data.filename || 'code_fix.ts');
          setSandboxOriginalCode(data.original_code || '');
          setSandboxPatchedCode(data.patched_code || '');
          setShowApprovalModal(true);
        } else if (data.type === 'echo') {
          addLog('info', data.message);
        }
      } catch (err) {
        addLog('info', `Raw response: ${event.data}`);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      addLog('system', 'Disconnected from WebSocket server.');
    };

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [sessionId]);

  
  // Fleet & Monorepo Engine Handlers
  const getParsedRepositories = () => {
    return fleetTargetRepo
      .split(/[\n,]+/)
      .map(r => r.trim())
      .filter(Boolean);
  };

  const handlePreviewFleet = async () => {
    setLoadingFleetPreview(true);
    try {
      const repos = getParsedRepositories();
      const resp = await fetch(getApiUrl('/api/v1/fleet/preview'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: repos.length > 0 ? repos : [fleetTargetRepo.trim()],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetPreviewPlan(data.plan);
      } else {
        alert(data.message || 'Failed to calculate fleet preview');
      }
    } catch (err: any) {
      alert(`Error previewing fleet: ${err.message}`);
    } finally {
      setLoadingFleetPreview(false);
    }
  };

  const handleLaunchFleetScan = async () => {
    setLoadingFleetScans(true);
    try {
      const repos = getParsedRepositories();
      const resp = await fetch(getApiUrl('/api/v1/fleet/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: repos.length > 0 ? repos : [fleetTargetRepo.trim()],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          max_concurrent_repos: 4,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        fetchFleetScans();
        const primaryRepo = repos[0] || fleetTargetRepo.trim();
        fetchRepoSummary(primaryRepo);
      } else {
        alert(data.message || 'Failed to launch fleet scan');
      }
    } catch (err: any) {
      alert(`Error launching fleet scan: ${err.message}`);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchFleetScans = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scans'));
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch fleet scans:', err);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchRepoSummary = async (repoName: string) => {
    setLoadingRepoSummary(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/summary`));
        const data = await resp.json();
        if (data.status === 'success') {
          setRepoSummary(data.data);
        }
      }
    } catch (err) {
      console.error('Failed to fetch repo summary:', err);
    } finally {
      setLoadingRepoSummary(false);
    }
  };

  const handleSyncMasterIssue = async (repoName: string) => {
    setSyncingMasterIssue(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/sync-master-issue`), {
          method: 'POST'
        });
        const data = await resp.json();
        if (data.status === 'success') {
          fetchRepoSummary(repoName);
        } else {
          alert(data.message || 'Failed to sync master issue');
        }
      }
    } catch (err: any) {
      alert(`Error syncing master issue: ${err.message}`);
    } finally {
      setSyncingMasterIssue(false);
    }
  };

  // Fetch GitOps patches
  const fetchPatches = async () => {
    setLoadingPatches(true);
    try {
      const response = await fetch(getApiUrl('/api/patches'));
      const data = await response.json();
      if (data.status === 'success') {
        setPatches(data.patches || []);
      }
    } catch (err) {
      console.error('Failed to fetch patches:', err);
    } finally {
      setLoadingPatches(false);
    }
  };

  // Fetch GitOps scans
  const fetchScans = async () => {
    setLoadingScans(true);
    try {
      const response = await fetch(getApiUrl('/api/scans'));
      const data = await response.json();
      if (data.status === 'success') {
        const activeScans = (data.scans || []).filter((s: any) => s.status !== 'SKIPPED');
        setScans(activeScans);
      }
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    } finally {
      setLoadingScans(false);
    }
  };

  const fetchAllData = () => {
    fetchPatches();
    fetchScans();
  };

  const fetchAnalytics = async (mode = dateFilterMode, start = startDate, end = endDate, repo = selectedRepo) => {
    setLoadingAnalytics(true);
    setLoadingRemediation(true);
    try {
      let queryParams = '';
      if (mode === 'today') {
        const today = getTodayUTC();
        queryParams = `start_date=${today}&end_date=${today}`;
      } else if (mode === 'yesterday') {
        const yest = getYesterdayUTC();
        queryParams = `start_date=${yest}&end_date=${yest}`;
      } else if (mode === '7d') {
        queryParams = `range_days=7`;
      } else if (mode === '30d') {
        queryParams = `range_days=30`;
      } else if (mode === 'custom') {
        if (start && end) {
          queryParams = `start_date=${start}&end_date=${end}`;
        } else if (start) {
          queryParams = `start_date=${start}`;
        } else {
          queryParams = `range_days=7`;
        }
      }

      // 1. Fetch Token analytics
      const tokenResp = await fetch(getApiUrl(`/api/analytics/tokens?${queryParams}`));
      const tokenData = await tokenResp.json();
      if (tokenData.status === 'success') {
        setAnalytics(tokenData);
      }

      // 2. Fetch Remediation analytics
      const repoParam = repo && repo !== 'all' ? `&repo_name=${encodeURIComponent(repo)}` : '';
      const remResp = await fetch(getApiUrl(`/api/analytics/remediation?${queryParams}${repoParam}`));
      const remData = await remResp.json();
      if (remData.status === 'success') {
        setRemediationData(remData);
        if (remData.repos && remData.repos.length > 0) {
          setAvailableRepos(remData.repos);
        }
      }
    } catch (err) {
      console.error('Failed to fetch analytics:', err);
    } finally {
      setLoadingAnalytics(false);
      setLoadingRemediation(false);
    }
  };

  const handleSelectRepo = (repo: string) => {
    setSelectedRepo(repo);
    fetchAnalytics(dateFilterMode, startDate, endDate, repo);
  };

  const handleSelectPreset = (mode: 'today' | 'yesterday' | '7d' | '30d') => {
    setDateFilterMode(mode);
    if (mode === 'today') {
      const today = getTodayUTC();
      setStartDate(today);
      setEndDate(today);
      fetchAnalytics('today', today, today, selectedRepo);
    } else if (mode === 'yesterday') {
      const yest = getYesterdayUTC();
      setStartDate(yest);
      setEndDate(yest);
      fetchAnalytics('yesterday', yest, yest, selectedRepo);
    } else if (mode === '7d') {
      setStartDate(getDaysAgoUTC(7));
      setEndDate(getTodayUTC());
      fetchAnalytics('7d', getDaysAgoUTC(7), getTodayUTC(), selectedRepo);
    } else if (mode === '30d') {
      setStartDate(getDaysAgoUTC(30));
      setEndDate(getTodayUTC());
      fetchAnalytics('30d', getDaysAgoUTC(30), getTodayUTC(), selectedRepo);
    }
  };

  const handleApplyCustomDate = () => {
    if (!startDate || !endDate) {
      alert('Please select both a Start Date and an End Date.');
      return;
    }
    if (startDate > endDate) {
      alert('Start Date cannot be after End Date.');
      return;
    }
    setDateFilterMode('custom');
    fetchAnalytics('custom', startDate, endDate, selectedRepo);
  };

  // Poll for patches and scans on mount
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Auto-refresh Fleet and Monorepo scans & posture every 3 seconds while on Fleet tab
  useEffect(() => {
    if (activeTab === 'fleet') {
      fetchFleetScans();
      if (fleetTargetRepo) {
        fetchRepoSummary(fleetTargetRepo);
      }
      const interval = setInterval(() => {
        fetchFleetScans();
        if (fleetTargetRepo) {
          fetchRepoSummary(fleetTargetRepo);
        }
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [activeTab, fleetTargetRepo]);

  // Fetch analytics when analytics tab is opened
  useEffect(() => {
    if (activeTab === 'analytics') {
      fetchAnalytics();
    }
  }, [activeTab]);


  // Autoscroll logs window
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const addLog = (type: string, message: string) => {
    setLogs((prev) => [...prev, { timestamp: new Date().toLocaleTimeString(), type, message }]);
  };

  const handleSubmit = async () => {
    if (!connected) {
      alert('WebSocket is not connected. Please wait or reload.');
      return;
    }

    setLoading(true);
    setQaReport(null);
    setSemanticReport(null);
    addLog('info', 'Submitting code submission for agent triage...');

    try {
      const response = await fetch(getApiUrl('/submit'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          code: code,
          intent: intent
        }),
      });

      const resData = await response.json();
      if (response.status !== 200) {
        addLog('error', `Submission failed: ${resData.detail}`);
        setLoading(false);
      } else {
        addLog('success', 'Submission accepted by backend API.');
      }
    } catch (err: any) {
      addLog('error', `Network error during submit: ${err.message}`);
      setLoading(false);
    }
  };

  const handleHITLDecision = (approve: boolean) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      alert('Websocket disconnected. Cannot transmit approval.');
      return;
    }

    const action = approve ? 'APPROVE' : 'REJECT';
    addLog('info', `Sending HITL decision: ${action}`);
    
    wsRef.current.send(JSON.stringify({ action }));
    setShowApprovalModal(false);
  };

  const handleVerify = async (commitSha: string, findingId: string) => {
    try {
      const response = await fetch(getApiUrl(`/api/scans/${commitSha}/verify/${findingId}`), {
        method: 'POST'
      });
      const data = await response.json();
      if (data.status === 'success') {
        fetchAllData();
      } else {
        alert(`Verification failed to queue: ${data.message}`);
      }
    } catch (err: any) {
      alert(`Network error: ${err.message}`);
    }
  };

  const handleFix = async (commitSha: string, findingId: string) => {
    try {
      const response = await fetch(getApiUrl(`/api/scans/${commitSha}/fix/${findingId}`), {
        method: 'POST'
      });
      const data = await response.json();
      if (data.status === 'success') {
        fetchAllData();
      } else {
        alert(`Patch generation failed to queue: ${data.message}`);
      }
    } catch (err: any) {
      alert(`Network error: ${err.message}`);
    }
  };

  const handleCancel = async (commitSha: string) => {
    if (!confirm('Are you sure you want to cancel this active scan/verification?')) return;
    try {
      const response = await fetch(getApiUrl(`/api/scans/${commitSha}/cancel`), {
        method: 'POST'
      });
      const data = await response.json();
      if (data.status === 'success') {
        fetchAllData();
      } else {
        alert(`Failed to cancel session: ${data.message}`);
      }
    } catch (err: any) {
      alert(`Network error: ${err.message}`);
    }
  };

  const openDismissModal = (commitSha: string, finding: any) => {
    setDismissCommitSha(commitSha);
    setDismissFinding(finding);
    setDismissCategory('FALSE_POSITIVE');
    setDismissReason('');
    setDismissModalOpen(true);
  };

  const handleConfirmDismissal = async () => {
    if (!dismissReason || dismissReason.trim().length < 10) {
      alert('Please provide a documented justification reason of at least 10 characters for risk acceptance audit compliance.');
      return;
    }
    setSubmittingDismissal(true);
    try {
      const resp = await fetch(getApiUrl(`/api/scans/${dismissCommitSha}/dismiss`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: dismissFinding.id,
          category: dismissCategory,
          reason: dismissReason.trim(),
          user: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        setDismissModalOpen(false);
        fetchScans();
      } else {
        alert(data.detail || data.error || 'Failed to dismiss finding');
      }
    } catch (err: any) {
      alert(`Error submitting dismissal: ${err.message}`);
    } finally {
      setSubmittingDismissal(false);
    }
  };

  return (
    <main className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Header Banner */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50 backdrop-blur">
        <div className="flex items-center space-x-3">
          <Shield className="h-6 w-6 text-indigo-400" />
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            CodeMender <span className="text-indigo-400">in Action</span>
          </h1>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-xs text-slate-400">Session ID: <code className="bg-slate-800 px-2 py-1 rounded text-slate-200">{sessionId}</code></span>
          <span className={`h-2.5 w-2.5 rounded-full ${connected ? 'bg-emerald-500' : 'bg-rose-500'} animate-pulse`} title={connected ? 'Connected' : 'Disconnected'} />
        </div>
      </header>

      {/* Navigation Tab Bar */}
      <div className="flex border-b border-slate-800 bg-slate-900/20 px-6 py-2 space-x-6">
        <button
          onClick={() => setActiveTab('gitops')}
          className={`pb-2 pt-1 text-sm font-semibold border-b-2 transition cursor-pointer ${
            activeTab === 'gitops'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          GitOps Pipeline Dashboard
        </button>
        <button
          onClick={() => setActiveTab('sandbox')}
          className={`pb-2 pt-1 text-sm font-semibold border-b-2 transition cursor-pointer ${
            activeTab === 'sandbox'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Interactive Sandbox
        </button>
        <button
          onClick={() => { setActiveTab('fleet'); fetchFleetScans(); fetchRepoSummary(fleetTargetRepo); }}
          className={`pb-2 pt-1 text-sm font-semibold border-b-2 transition cursor-pointer flex items-center space-x-1.5 ${
            activeTab === 'fleet'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>Fleet & Monorepo Scaling</span>
        </button>
        <button
          onClick={() => setActiveTab('analytics')}
          className={`pb-2 pt-1 text-sm font-semibold border-b-2 transition cursor-pointer ${
            activeTab === 'analytics'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Token Usage & Costs
        </button>
      </div>

      {/* Main Container switching based on Active Tab */}
      {activeTab === 'gitops' ? (
        /* ==================== GITOPS DASHBOARD TAB ==================== */
        <div className="flex-1 flex flex-col p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-100">Pull Request Patch Proposals</h2>
              <p className="text-xs text-slate-400">Monitors code vulnerability scans and proposed patches from GitOps checkouts.</p>
            </div>
            <button
              onClick={fetchAllData}
              disabled={loadingPatches || loadingScans}
              className="flex items-center space-x-1.5 py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded transition text-slate-200 cursor-pointer"
            >
              {loadingPatches || loadingScans ? <Loader className="h-3.5 w-3.5 animate-spin" /> : null}
              <span>Refresh Scan Feed</span>
            </button>
          </div>

          {/* Vulnerability Scans Section */}
          {scans.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-indigo-400">Vulnerability Scans Feed</h3>
              <div className="grid grid-cols-1 gap-4">
                {scans.map((scan, idx) => (
                  <div key={idx} className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition flex flex-col space-y-4">
                    
                    {/* Header Row */}
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-3 flex-wrap gap-y-1">
                          {scan.pr_number ? (
                            <a
                              href={scan.pr_url || `https://github.com/${scan.repo_name || 'your-org/your-repo'}/pull/${scan.pr_number}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-bold text-slate-100 hover:text-indigo-400 transition flex items-center space-x-1.5 underline decoration-slate-700 hover:decoration-indigo-400"
                            >
                              <span>{scan.is_draft ? '📝 Draft PR' : '🚀 Pull Request'} #{scan.pr_number}</span>
                              <span className="text-xs font-normal text-slate-400">({scan.branch_name}{scan.base_branch ? ` ➔ ${scan.base_branch}` : ''})</span>
                            </a>
                          ) : (
                            <span className="font-bold text-slate-200">Scan for Branch: {scan.branch_name}</span>
                          )}
                          <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full border ${
                            scan.status === 'COMPLETED'
                              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
                              : scan.status === 'FAILED'
                                ? 'bg-rose-950/40 border-rose-500/30 text-rose-400'
                                : 'bg-indigo-950/40 border-indigo-500/30 text-indigo-400 animate-pulse'
                          }`}>
                            {scan.status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 flex items-center space-x-3 flex-wrap gap-y-1">
                          <span>Head SHA: <code className="bg-slate-800 px-1.5 py-0.5 rounded font-mono text-[11px] text-slate-300">{scan.commit_sha?.substring(0, 7)}</code></span>
                          <span>•</span>
                          <span>Repo: <span className="text-slate-300 font-medium">{scan.repo_name || 'default'}</span></span>
                          <span>•</span>
                          <span>Updated: {scan.updated_at ? new Date(scan.updated_at * 1000).toLocaleString() : 'N/A'}</span>
                        </div>
                      </div>

                      {scan.status !== 'COMPLETED' && scan.status !== 'FAILED' && (
                        <div className="flex items-center space-x-3 text-xs text-indigo-400 font-semibold">
                          <div className="flex items-center space-x-1.5">
                            <Loader className="h-4 w-4 animate-spin" />
                            <span>{scan.message}</span>
                          </div>
                          <button
                            onClick={() => handleCancel(scan.commit_sha)}
                            className="text-[11px] px-2.5 py-1 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 font-semibold border border-rose-500/30 rounded cursor-pointer transition flex items-center space-x-1"
                          >
                            <span>🛑 Cancel / Reset Task</span>
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Findings Block */}
                    {scan.findings && scan.findings.length > 0 ? (
                      <div className="space-y-3 pt-2 border-t border-slate-800/60">
                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Detected Vulnerabilities</h4>
                        <div className="space-y-2">
                          {scan.findings.map((finding: any, fIdx: number) => (
                            <div key={fIdx} className="bg-slate-950/50 border border-slate-800/60 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                              <div className="space-y-1.5 flex-1">
                                <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                                  <AlertTriangle className={`h-4 w-4 ${
                                    finding.status === 'DISMISSED' ? 'text-slate-500' :
                                    finding.severity === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'
                                  }`} />
                                  <span className={`font-bold text-sm ${finding.status === 'DISMISSED' ? 'text-slate-400 line-through' : 'text-slate-200'}`}>
                                    {finding.vuln_type}
                                  </span>
                                  <span className="text-[10px] font-mono bg-slate-900 text-slate-400 px-1.5 py-0.5 rounded border border-slate-800">
                                    ID: {finding.id}
                                  </span>
                                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase border ${
                                    finding.severity === 'CRITICAL' ? 'bg-rose-950/40 border-rose-600/30 text-rose-300' :
                                    finding.severity === 'HIGH' ? 'bg-orange-950/40 border-orange-600/30 text-orange-300' :
                                    'bg-amber-950/40 border-amber-600/30 text-amber-300'
                                  }`}>
                                    {finding.severity || 'CRITICAL'}
                                  </span>
                                </div>
                                <p className="text-xs text-slate-400">File: <code className="font-mono text-slate-300">{finding.filepath}</code></p>
                                {finding.description && <p className="text-xs text-slate-400">{finding.description}</p>}
                                
                                {finding.status === 'DISMISSED' && finding.dismissal && (
                                  <div className="mt-2 bg-amber-950/20 border border-amber-500/20 rounded-md p-2 text-xs text-amber-300/90 space-y-1">
                                    <div className="flex items-center space-x-1.5 font-semibold text-[11px] text-amber-400">
                                      <Shield className="h-3 w-3" />
                                      <span>Risk Accepted: [{finding.dismissal.category}] by @{finding.dismissal.dismissed_by}</span>
                                    </div>
                                    <p className="text-[11px] text-slate-300 italic">"{finding.dismissal.reason}"</p>
                                  </div>
                                )}
                              </div>

                              <div className="flex items-center space-x-2 shrink-0">
                                {finding.status === 'DISMISSED' ? (
                                  <span className="text-xs text-amber-400 bg-amber-950/40 border border-amber-500/30 px-2.5 py-1 rounded font-semibold flex items-center space-x-1">
                                    <AlertTriangle className="h-3.5 w-3.5" />
                                    <span>Dismissed</span>
                                  </span>
                                ) : (
                                  <>
                                    {/* Verify Action */}
                                    {finding.status === 'DETECTED' || finding.status === 'VERIFICATION_FAILED' ? (
                                      <button
                                        onClick={() => handleVerify(scan.commit_sha, finding.id)}
                                        className="py-1 px-3 bg-indigo-600/80 hover:bg-indigo-500 text-white text-xs font-semibold rounded transition cursor-pointer"
                                      >
                                        Verify Exploit
                                      </button>
                                    ) : finding.status === 'VERIFYING' ? (
                                      <span className="text-xs text-indigo-400 flex items-center space-x-1.5 px-3 py-1 font-semibold">
                                        <Loader className="h-3.5 w-3.5 animate-spin" />
                                        <span>Verifying...</span>
                                      </span>
                                    ) : (
                                      <span className="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2.5 py-1 rounded font-semibold flex items-center space-x-1">
                                        <Check className="h-3.5 w-3.5" />
                                        <span>Exploit Verified</span>
                                      </span>
                                    )}

                                    {/* Fix Action */}
                                    {finding.status === 'VERIFIED' || finding.status === 'PATCH_FAILED' ? (
                                      <button
                                        onClick={() => handleFix(scan.commit_sha, finding.id)}
                                        className="py-1 px-3 bg-emerald-600/80 hover:bg-emerald-500 text-white text-xs font-semibold rounded transition cursor-pointer"
                                      >
                                        Generate Fix
                                      </button>
                                    ) : finding.status === 'PATCHING' ? (
                                      <span className="text-xs text-emerald-400 flex items-center space-x-1.5 px-3 py-1 font-semibold">
                                        <Loader className="h-3.5 w-3.5 animate-spin" />
                                        <span>Generating...</span>
                                      </span>
                                    ) : finding.status === 'PATCHED' ? (
                                      <div className="flex items-center space-x-2">
                                        <span className="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2.5 py-1 rounded font-semibold flex items-center space-x-1">
                                          <Check className="h-3.5 w-3.5" />
                                          <span>Patched (PR Drafted)</span>
                                        </span>
                                        {scan.pr_number && (
                                          <button
                                            onClick={() => handleInspectScanPatch(scan.pr_number)}
                                            className="py-1 px-2.5 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/20 text-xs font-semibold rounded transition cursor-pointer"
                                          >
                                            Inspect Diff
                                          </button>
                                        )}
                                      </div>
                                    ) : null}

                                    {/* Dismiss / Accept Risk Action */}
                                    {finding.status !== 'PATCHED' && (
                                      <button
                                        onClick={() => openDismissModal(scan.commit_sha, finding)}
                                        className="py-1 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold rounded border border-slate-700 transition cursor-pointer"
                                        title="Dismiss finding / Accept risk"
                                      >
                                        Dismiss
                                      </button>
                                    )}
                                  </>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : scan.status === 'COMPLETED' ? (
                      <div className="bg-slate-950/30 border border-slate-800/40 rounded-lg p-3 text-xs text-emerald-400 flex items-center space-x-2">
                        <CheckCircle className="h-4 w-4" />
                        <span>No vulnerabilities identified in this scan. Code is secure!</span>
                      </div>
                    ) : scan.status === 'FAILED' ? (
                      <div className="bg-rose-950/10 border border-rose-500/10 rounded-lg p-3 text-xs text-rose-400 flex items-center space-x-2">
                        <AlertTriangle className="h-4 w-4" />
                        <span>Scan failed: {scan.message}</span>
                      </div>
                    ) : null}

                    {/* Research Artifacts (Cloud Storage) */}
                    {scan.artifacts && scan.artifacts.length > 0 && (
                      <div className="pt-2 flex flex-col space-y-1.5 border-t border-slate-800/40">
                        <h5 className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Research Artifacts (Cloud Storage)</h5>
                        <div className="flex flex-wrap gap-2">
                          {scan.artifacts.map((art: any, aIdx: number) => (
                            <a
                              key={aIdx}
                              href={art.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700/80 text-slate-300 hover:text-slate-200 border border-slate-700/50 hover:border-slate-600 rounded text-[11px] font-medium transition cursor-pointer"
                            >
                              <Paperclip className="h-3 w-3 text-indigo-400" />
                              <span>{art.name}</span>
                            </a>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Collapsible Action Bar for Timeline & Console logs */}
                    <div className="flex items-center space-x-4 pt-2.5 border-t border-slate-800/40 text-xs">
                      {scan.steps && scan.steps.length > 0 && (
                        <button
                          onClick={() => toggleTimeline(scan.commit_sha)}
                          className="flex items-center space-x-1 text-slate-400 hover:text-slate-200 cursor-pointer font-semibold"
                        >
                          <span>{expandedTimelines[scan.commit_sha] ? '▼ Hide Steps' : '▶ View Execution Steps'}</span>
                        </button>
                      )}
                      {scan.logs && Object.keys(scan.logs).length > 0 && (
                        <button
                          onClick={() => {
                            toggleConsole(scan.commit_sha);
                            // Set default active tab
                            if (!activeLogTabs[scan.commit_sha]) {
                              const keys = Object.keys(scan.logs);
                              if (keys.includes('fix_output')) selectLogTab(scan.commit_sha, 'fix');
                              else if (keys.includes('verify_output')) selectLogTab(scan.commit_sha, 'verify');
                              else selectLogTab(scan.commit_sha, 'find');
                            }
                          }}
                          className="flex items-center space-x-1 text-indigo-400 hover:text-indigo-300 cursor-pointer font-semibold"
                        >
                          <span>{expandedConsoles[scan.commit_sha] ? '▼ Hide Console Logs' : '▶ View Console Logs'}</span>
                        </button>
                      )}
                    </div>

                    {/* Timeline steps render panel */}
                    {expandedTimelines[scan.commit_sha] && scan.steps && (
                      <div className="bg-slate-950/40 rounded-lg p-4 border border-slate-800/60 flex flex-col space-y-2 font-mono text-[11px] max-h-[250px] overflow-y-auto">
                        <h5 className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">Execution Steps History</h5>
                        {scan.steps.map((step: any, sIdx: number) => (
                          <div key={sIdx} className="flex items-start space-x-2 leading-relaxed">
                            <span className="text-slate-600 shrink-0">[{new Date(step.timestamp * 1000).toLocaleTimeString()}]</span>
                            <span className={`font-semibold shrink-0 uppercase text-[9px] px-1 rounded ${
                              step.type === 'error' ? 'bg-rose-900/40 text-rose-400' :
                              step.type === 'warning' ? 'bg-amber-900/40 text-amber-400' :
                              step.type === 'gitops' ? 'bg-emerald-900/40 text-emerald-400' :
                              step.type === 'workspace' ? 'bg-slate-800 text-indigo-400' :
                              'bg-slate-800 text-slate-400'
                            }`}>
                              {step.type}
                            </span>
                            <span className="text-slate-300">{step.message}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Collapsible log console tabbed panel */}
                    {expandedConsoles[scan.commit_sha] && scan.logs && (
                      <div className="bg-slate-950 border border-slate-800 rounded-lg flex flex-col overflow-hidden max-h-[350px]">
                        {/* Tab header buttons */}
                        <div className="flex bg-slate-900/40 border-b border-slate-800 px-3 py-1 space-x-2">
                          {scan.logs.find_output && (
                            <button
                              onClick={() => selectLogTab(scan.commit_sha, 'find')}
                              className={`px-3 py-1 text-[11px] font-semibold border-b-2 transition cursor-pointer ${
                                (activeLogTabs[scan.commit_sha] || 'find') === 'find' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'
                              }`}
                            >
                              Scanner CLI Log
                            </button>
                          )}
                          {scan.logs.verify_output && (
                            <button
                              onClick={() => selectLogTab(scan.commit_sha, 'verify')}
                              className={`px-3 py-1 text-[11px] font-semibold border-b-2 transition cursor-pointer ${
                                activeLogTabs[scan.commit_sha] === 'verify' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'
                              }`}
                            >
                              Verification Log
                            </button>
                          )}
                          {scan.logs.fix_output && (
                            <button
                              onClick={() => selectLogTab(scan.commit_sha, 'fix')}
                              className={`px-3 py-1 text-[11px] font-semibold border-b-2 transition cursor-pointer ${
                                activeLogTabs[scan.commit_sha] === 'fix' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'
                              }`}
                            >
                              Fix Agent Log
                            </button>
                          )}
                        </div>
                        
                        {/* Tab contents viewport */}
                        <div className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed text-slate-300 max-h-[250px] whitespace-pre-wrap">
                          {((activeLogTabs[scan.commit_sha] || 'find') === 'find') && scan.logs.find_output && (
                            <code>{scan.logs.find_output}</code>
                          )}
                          {(activeLogTabs[scan.commit_sha] === 'verify') && scan.logs.verify_output && (
                            <code>{scan.logs.verify_output}</code>
                          )}
                          {(activeLogTabs[scan.commit_sha] === 'fix') && scan.logs.fix_output && (
                            <code>{scan.logs.fix_output}</code>
                          )}
                        </div>
                      </div>
                    )}

                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Proposed Patches</h3>
            {patches.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center p-12 border border-dashed border-slate-800 rounded-xl bg-slate-900/10">
                <Shield className="h-12 w-12 text-slate-700 mb-3" />
                <h3 className="font-bold text-slate-400 mb-1">No GitOps patches proposed yet</h3>
                <p className="text-xs text-slate-500 text-center max-w-sm">
                  Push code commits to development/feature branches on GitHub to trigger automatic scans and generate patch proposals.
                </p>
              </div>
            ) : (


            <div className="grid grid-cols-1 gap-4">
              {patches.map((patch, idx) => (
                <div key={idx} className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition flex flex-col space-y-4">
                  
                  {/* Proposal Top Metadata Row */}
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-3">
                        <span className="font-bold text-slate-200">Pull Request #{patch.pr_number}</span>
                        <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full border ${
                          patch.is_applied
                            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
                            : 'bg-amber-950/40 border-amber-500/30 text-amber-400'
                        }`}>
                          {patch.is_applied ? 'applied' : 'proposed (pending /approve)'}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 flex items-center space-x-4">
                        <span>Branch: <code className="bg-slate-800 px-1.5 py-0.5 rounded font-mono text-[11px] text-slate-300">{patch.branch_name}</code></span>
                        <span>•</span>
                        <span>Commit SHA: <code className="bg-slate-800 px-1.5 py-0.5 rounded font-mono text-[11px] text-slate-300">{patch.commit_sha?.substring(0, 7)}</code></span>
                        <span>•</span>
                        <span>Scanned: {patch.created_at ? new Date(patch.created_at * 1000).toLocaleString() : 'N/A'}</span>
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        setFilename(patch.filename);
                        setGitDiff(patch.git_diff);
                        setPatchedCode(patch.patched_code);
                        setInspectionTab('diff');
                        setShowInspectionModal(true);
                      }}
                      className="flex items-center space-x-1 py-1.5 px-3.5 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 text-xs font-semibold rounded border border-indigo-500/20 transition cursor-pointer"
                    >
                      <span>Inspect Proposed Patch</span>
                    </button>
                  </div>

                  {/* File context info block */}
                  <div className="bg-slate-950/50 border border-slate-800/60 rounded-lg p-3 text-xs flex items-center space-x-2 text-slate-300">
                    <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">Target File</span>
                    <span className="font-mono">{patch.filename}</span>
                  </div>

                  {/* GitOps Instruction banner */}
                  {!patch.is_applied && (
                    <div className="bg-amber-950/10 border border-amber-500/10 rounded-lg px-4 py-2.5 text-xs text-amber-300 leading-relaxed flex items-start space-x-2">
                      <span className="font-bold text-amber-400">👉 GitOps Flow:</span>
                      <span>To apply this security fix and merge it into the branch, comment <code className="bg-amber-950/40 border border-amber-900/60 px-1.5 py-0.5 rounded text-amber-300">/approve</code> on pull request conversation.</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    ) : activeTab === 'sandbox' ? (
        /* ==================== PLAYGROUND SANDBOX TAB ==================== */
        <div className="flex-1 flex overflow-hidden">
          {/* Editor Area (Left 60%) */}
          <div className="w-[60%] flex flex-col border-r border-slate-800">
            <div className="flex-1 min-h-[400px]">
              <Editor
                height="100%"
                defaultLanguage="javascript"
                theme="vs-dark"
                value={code}
                onChange={(value) => setCode(value || '')}
                options={{
                  fontSize: 14,
                  minimap: { enabled: false },
                  lineHeight: 22,
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
            
            {/* Submit Panel */}
            <div className="p-4 border-t border-slate-800 bg-slate-900/30 flex flex-col space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-400 block mb-1">PROMPT / INTENT</label>
                <input
                  type="text"
                  value={intent}
                  onChange={(e) => setIntent(e.target.value)}
                  placeholder="What should the agent check or fix?"
                  className="w-full bg-slate-800/80 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-indigo-500 transition"
                />
              </div>
              <button
                onClick={handleSubmit}
                disabled={loading}
                className="flex items-center justify-center space-x-2 py-2.5 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-sm font-semibold rounded transition shadow-lg shadow-indigo-600/10 cursor-pointer"
              >
                {loading ? (
                  <>
                    <Loader className="h-4 w-4 animate-spin" />
                    <span>Processing Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 fill-current" />
                    <span>Submit for Review</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Sidebar Results Area (Right 40%) */}
          <div className="w-[40%] flex flex-col bg-slate-900/20 overflow-y-auto p-6 space-y-6">
            {/* Status Reports section */}
            <div>
              <h2 className="text-sm font-semibold text-slate-400 tracking-wider mb-3 flex items-center space-x-2">
                <Code className="h-4 w-4 text-indigo-400" />
                <span>AGENT PRE-CHECK STATUS</span>
              </h2>
              
              <div className="grid grid-cols-1 gap-4">
                {/* QA Intent Report */}
                <div className={`p-4 rounded border transition ${
                  qaReport 
                    ? (qaReport.matches_intent ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-100' : 'bg-rose-950/20 border-rose-800/40 text-rose-100')
                    : 'bg-slate-900/50 border-slate-800/80 text-slate-400'
                }`}>
                  <div className="flex items-center space-x-2 mb-1.5">
                    {qaReport ? (
                      qaReport.matches_intent ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-rose-400" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-slate-500" />
                    )}
                    <h3 className="font-bold text-sm">QA Intent Checker</h3>
                  </div>
                  <p className="text-xs leading-relaxed">
                    {qaReport ? qaReport.feedback : 'Waiting for submission analysis...'}
                  </p>
                </div>

                {/* Semantic Hygiene Report */}
                <div className={`p-4 rounded border transition ${
                  semanticReport 
                    ? (semanticReport.has_secrets ? 'bg-rose-950/20 border-rose-800/40 text-rose-100' : 'bg-emerald-950/20 border-emerald-800/40 text-emerald-100')
                    : 'bg-slate-900/50 border-slate-800/80 text-slate-400'
                }`}>
                  <div className="flex items-center space-x-2 mb-1.5">
                    {semanticReport ? (
                      semanticReport.has_secrets ? <XCircle className="h-4 w-4 text-rose-400" /> : <CheckCircle className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-slate-500" />
                    )}
                    <h3 className="font-bold text-sm">Security & Hygiene Report</h3>
                  </div>
                  <div className="text-xs leading-relaxed">
                    {semanticReport ? (
                      <>
                        <p className="mb-2 font-semibold">
                          {semanticReport.has_secrets ? '🔴 High Risk: Secrets / API keys detected.' : '✅ Secure: No hardcoded secrets.'}
                        </p>
                        {semanticReport.hygiene_issues.length > 0 && (
                          <ul className="list-disc pl-4 space-y-1">
                            {semanticReport.hygiene_issues.map((issue, idx) => (
                              <li key={idx}>{issue}</li>
                            ))}
                          </ul>
                        )}
                      </>
                    ) : (
                      'Waiting for submission analysis...'
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Reasoning console section */}
            <div className="flex-1 flex flex-col">
              <h2 className="text-sm font-semibold text-slate-400 tracking-wider mb-3 flex items-center space-x-2">
                <MessageSquare className="h-4 w-4 text-indigo-400" />
                <span>LIVE AGENT REASONING CONSOLE</span>
              </h2>
              <div 
                ref={logContainerRef}
                className="flex-1 min-h-[250px] bg-slate-950 border border-slate-800 rounded p-4 font-mono text-xs overflow-y-auto space-y-2.5 max-h-[400px]"
              >
                {logs.length === 0 ? (
                  <div className="text-slate-600 italic">Logs are empty. Submit code to start streaming.</div>
                ) : (
                  logs.map((log, idx) => (
                    <div key={idx} className="flex items-start space-x-2 leading-relaxed">
                      <span className="text-slate-600 shrink-0">{log.timestamp}</span>
                      <span className={`font-semibold shrink-0 uppercase text-[10px] px-1 rounded ${
                        log.type === 'system' ? 'bg-slate-800 text-slate-400' :
                        log.type === 'error' ? 'bg-rose-900/40 text-rose-400 border border-rose-800/30' :
                        log.type === 'success' ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-800/30' :
                        log.type === 'warning' ? 'bg-amber-900/40 text-amber-400 border border-amber-800/30' :
                        'bg-indigo-900/40 text-indigo-400 border border-indigo-800/30'
                      }`}>
                        {log.type}
                      </span>
                      <span className="text-slate-300 break-all">{log.message}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      ) : activeTab === 'fleet' ? (
        /* ==================== FLEET & MONOREPO ENGINE TAB ==================== */
        <div className="flex-1 flex flex-col p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
                <Layers className="h-5 w-5 text-indigo-400" />
                <span>Enterprise Monorepo & Fleet Scaling Engine</span>
              </h2>
              <p className="text-xs text-slate-400">Subtree AST sharding, toolchain auto-detection, In-Repo Master Assessment Issues, and SLA compliance tracking.</p>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={() => { fetchFleetScans(); fetchRepoSummary(fleetTargetRepo); }}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold rounded transition cursor-pointer"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loadingFleetScans ? 'animate-spin' : ''}`} />
                <span>Refresh Fleet</span>
              </button>
            </div>
          </div>

          {/* Top 2-Column Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Card 1: Monorepo Discovery & Pre-Flight Sizing */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2">
                  <Server className="h-4 w-4 text-indigo-400" />
                  <h3 className="text-sm font-bold text-slate-200">Monorepo Discovery & Sizing Calculator</h3>
                </div>
                <span className="text-[10px] bg-indigo-900/40 text-indigo-400 border border-indigo-800/40 px-2 py-0.5 rounded font-mono">Stage 1 Pre-Flight</span>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-1">AUDIT SCOPE</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(['EXPLICIT_LIST', 'ORGANIZATION', 'TOPIC_FILTER'] as const).map(scope => (
                      <button
                        key={scope}
                        onClick={() => setFleetScopeType(scope)}
                        className={`py-1.5 text-xs font-semibold rounded border transition cursor-pointer ${
                          fleetScopeType === scope
                            ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300'
                            : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {scope.replace('_', ' ')}
                      </button>
                    ))}
                  </div>
                </div>

                {fleetScopeType === 'EXPLICIT_LIST' && (
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1">TARGET MONOREPO / REPOSITORIES (ONE PER LINE OR COMMA-SEPARATED)</label>
                    <textarea
                      rows={3}
                      value={fleetTargetRepo}
                      onChange={(e) => setFleetTargetRepo(e.target.value)}
                      placeholder={`e.g.\nyour-org/your-repo`}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition font-mono resize-y"
                    />
                  </div>
                )}

                {fleetScopeType === 'ORGANIZATION' && (
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1">ORGANIZATION NAME</label>
                    <input
                      type="text"
                      value={fleetOrg}
                      onChange={(e) => setFleetOrg(e.target.value)}
                      placeholder="e.g. your-org"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition font-mono"
                    />
                  </div>
                )}

                {fleetScopeType === 'TOPIC_FILTER' && (
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1">TOPIC TAGS (COMMA-SEPARATED)</label>
                    <input
                      type="text"
                      value={fleetTopics}
                      onChange={(e) => setFleetTopics(e.target.value)}
                      placeholder="e.g. security, production, monorepo"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition font-mono"
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1">MONOREPO LOC THRESHOLD</label>
                    <input
                      type="number"
                      value={monorepoLocThreshold}
                      onChange={(e) => setMonorepoLocThreshold(Number(e.target.value))}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1">GEMINI MODEL TIER</label>
                    <select
                      value={fleetModelTier}
                      onChange={(e) => setFleetModelTier(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition [color-scheme:dark]"
                    >
                      <option value="gemini-3.8-flash">Gemini 3.8 Flash (Cloud Billing Discount)</option>
                      <option value="gemini-3.5-flash">Gemini 3.5 Flash ($0.15/1M)</option>
                      <option value="gemini-3.1-pro">Gemini 3.1 Pro ($1.25/1M)</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center space-x-3 pt-2">
                  <button
                    onClick={handlePreviewFleet}
                    disabled={loadingFleetPreview}
                    className="flex-1 flex items-center justify-center space-x-2 py-2 px-3 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded border border-slate-700 text-slate-200 transition cursor-pointer"
                  >
                    {loadingFleetPreview ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Filter className="h-3.5 w-3.5 text-indigo-400" />}
                    <span>Preview Sizing & Shards</span>
                  </button>
                  <button
                    onClick={handleLaunchFleetScan}
                    disabled={loadingFleetScans}
                    className="flex-1 flex items-center justify-center space-x-2 py-2 px-3 bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold rounded text-white transition shadow-lg shadow-indigo-600/20 cursor-pointer"
                  >
                    {loadingFleetScans ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                    <span>Launch Monorepo Scan</span>
                  </button>
                </div>

                {/* Sizing Preview Output */}
                {fleetPreviewPlan && (
                  <div className="mt-4 p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-300">Monorepo Sizing Analysis:</span>
                      <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                        fleetPreviewPlan.execution_mode === 'MONOREPO_SHARDED'
                          ? 'bg-amber-900/40 text-amber-300 border border-amber-800/40'
                          : 'bg-emerald-900/40 text-emerald-300 border border-emerald-800/40'
                      }`}>
                        {fleetPreviewPlan.execution_mode || 'MONOREPO_SHARDED'}
                      </span>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-400 block">Total Repos / Modules</span>
                        <span className="font-bold text-slate-100">{fleetPreviewPlan.total_repos ?? 0}</span>
                      </div>
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-400 block">Estimated Shards</span>
                        <span className="font-bold text-indigo-400">{fleetPreviewPlan.shards_count ?? 0}</span>
                      </div>
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-400 block">Estimated Cost</span>
                        <span className="font-bold text-emerald-400">${Number(fleetPreviewPlan.estimated_cost_usd ?? 0).toFixed(3)}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Card 2: In-Repo Master Assessment Issue & Posture Live Card */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <CheckSquare className="h-4 w-4 text-emerald-400" />
                    <h3 className="text-sm font-bold text-slate-200">In-Repo Master Assessment Issue & SLA Posture</h3>
                  </div>
                  <button
                    onClick={() => handleSyncMasterIssue(fleetTargetRepo)}
                    disabled={syncingMasterIssue}
                    className="flex items-center space-x-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-semibold rounded text-slate-200 transition cursor-pointer"
                  >
                    {syncingMasterIssue ? <Loader className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3 text-emerald-400" />}
                    <span>Sync GitHub Master Issue</span>
                  </button>
                </div>

                <div className="pt-3 space-y-4">
                  <div className="flex items-center justify-between bg-slate-950 p-4 rounded-xl border border-slate-800">
                    <div>
                      <span className="text-xs text-slate-400 block">Repository Security Posture:</span>
                      <span className="font-mono text-sm font-bold text-slate-100">{fleetTargetRepo}</span>
                      <div className="mt-2 text-xs font-mono text-indigo-400">
                        Remediation Progress: <span className="text-slate-100 font-bold">{repoSummary?.posture?.progress_bar || (loadingRepoSummary ? 'Calculating...' : '[░░░░░░░░░░] 0%')}</span>
                      </div>
                    </div>
                    <div className="flex flex-col items-center justify-center h-16 w-16 rounded-2xl bg-indigo-950/60 border border-indigo-800/40 text-center">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Grade</span>
                      <span className="text-2xl font-black text-indigo-400">{repoSummary?.posture?.security_grade || (loadingRepoSummary ? '...' : '-')}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-4 gap-2 text-center text-xs">
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Total Issues</span>
                      <span className="font-bold text-slate-200">{repoSummary?.posture?.total_findings ?? 0}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Active</span>
                      <span className="font-bold text-rose-400">{repoSummary?.posture?.active_findings ?? 0}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Remediated</span>
                      <span className="font-bold text-emerald-400">{repoSummary?.posture?.resolved_findings ?? 0}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">SLA Breaches</span>
                      <span className="font-bold text-amber-400">{repoSummary?.posture?.sla_breaches_count ?? 0}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-3 bg-slate-950/60 border border-slate-800/60 rounded-lg text-[11px] text-slate-400 flex items-center justify-between">
                <span>GitHub Issue Link:</span>
                <span className="font-mono text-indigo-400 font-semibold">{repoSummary?.posture?.master_issue_url ? (
                  <a href={repoSummary.posture.master_issue_url} target="_blank" rel="noreferrer" className="underline hover:text-indigo-300">
                    #{repoSummary.posture.master_issue_number} Security Posture Report
                  </a>
                ) : (
                  'Auto-Managed (#1 Master Issue)'
                )}</span>
              </div>
            </div>
          </div>

          {/* Bottom Table: Active Fleet Scans & Shard Execution Monitor */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Zap className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-bold text-slate-200">Monorepo Shard Scanner & Execution Queue</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">Parallel Argo / Cloud Run Map-Reduce Workers</span>
            </div>

            {fleetScans.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] border-b border-slate-800 font-mono">
                    <tr>
                      <th className="py-2.5 px-3">Scan ID</th>
                      <th className="py-2.5 px-3">Scope / Target</th>
                      <th className="py-2.5 px-3">Execution Status</th>
                      <th className="py-2.5 px-3">Shards Progress</th>
                      <th className="py-2.5 px-3">Model Tier</th>
                      <th className="py-2.5 px-3">Triggered</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {fleetScans.map((fs: any, idx: number) => {
                      const scanId = fs.fleet_scan_id || fs.scan_id || `fleet-${idx+1}`;
                      const isExpanded = selectedFleetScanId === scanId;
                      const targetDisplay = fs.repositories?.[0]?.repo_name || fs.organization || fs.scope_type || fleetTargetRepo;
                      const isCompleted = fs.status === 'COMPLETED';
                      const isScanning = fs.status === 'SCANNING' || fs.status === 'RUNNING';
                      const isFailed = fs.status === 'FAILED';

                      return (
                        <React.Fragment key={idx}>
                          <tr
                            onClick={() => setSelectedFleetScanId(isExpanded ? null : scanId)}
                            className="hover:bg-slate-800/40 transition cursor-pointer"
                          >
                            <td className="py-3 px-3 text-indigo-400 font-bold flex items-center space-x-2">
                              <span>{isExpanded ? '▼' : '▶'}</span>
                              <span>{scanId}</span>
                            </td>
                            <td className="py-3 px-3 text-slate-200">{targetDisplay}</td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isCompleted ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-800/40' :
                                isScanning ? 'bg-indigo-900/40 text-indigo-400 border border-indigo-800/40 animate-pulse' :
                                isFailed ? 'bg-rose-900/40 text-rose-400 border border-rose-800/40' :
                                'bg-amber-900/40 text-amber-400 border border-amber-800/40'
                              }`}>
                                {fs.status || 'READY'}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-slate-300">
                              <div className="flex items-center space-x-2">
                                <span>{fs.completed_shards || (isCompleted ? 1 : 0)}/{fs.total_shards || 1} Shards</span>
                                <span className="text-slate-500 text-[10px]">{isCompleted ? '[■■■■■] 100%' : isScanning ? '[■■■░░] 60%' : '[░░░░░] 0%'}</span>
                              </div>
                            </td>
                            <td className="py-3 px-3 text-slate-400">{fs.model_tier || 'gemini-3.8-flash'}</td>
                            <td className="py-3 px-3 text-slate-500">{fs.created_at ? new Date(fs.created_at * 1000).toLocaleTimeString() : 'Just now'}</td>
                          </tr>

                          {/* Expandable Shard & Module Detail Drawer */}
                          {isExpanded && (
                            <tr className="bg-slate-950/90 border-b border-slate-800/80">
                              <td colSpan={6} className="p-4 space-y-3">
                                <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
                                  <div className="flex items-center space-x-2">
                                    <Activity className="h-4 w-4 text-indigo-400" />
                                    <span className="text-xs font-bold text-slate-200">Distributed Execution & Shard Telemetry: {scanId}</span>
                                  </div>
                                  <div className="flex items-center space-x-3 text-[11px]">
                                    <span className="text-slate-400">Total Analyzable LOC: <strong className="text-slate-200 font-mono">{fs.total_loc ?? 0}</strong></span>
                                    <span className="text-slate-400">Est. Cost: <strong className="text-emerald-400 font-mono">${Number(fs.estimated_cost_usd ?? 0).toFixed(4)}</strong></span>
                                  </div>
                                </div>

                                {/* Monorepo Shard Worker Breakdown Table */}
                                <div className="space-y-2">
                                  <span className="text-[11px] font-semibold text-slate-400 block uppercase">Subtree Modules & Map-Reduce Workers</span>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {(fs.repositories || [{ repo_name: targetDisplay, status: fs.status, shards: 1, target_engine: 'SINGLE_POD_JOB', estimated_loc: fs.total_loc }]).map((repoItem: any, rIdx: number) => (
                                      <div key={rIdx} className="bg-slate-900 p-3 rounded-lg border border-slate-800 space-y-1.5">
                                        <div className="flex items-center justify-between text-xs">
                                          <span className="font-bold text-indigo-300 font-mono">{repoItem.repo_name}</span>
                                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                            repoItem.status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50' :
                                            repoItem.status === 'FAILED' ? 'bg-rose-950 text-rose-300 border border-rose-800/50' :
                                            'bg-indigo-950 text-indigo-300 border border-indigo-800/50 animate-pulse'
                                          }`}>
                                            {repoItem.status || fs.status}
                                          </span>
                                        </div>
                                        <div className="grid grid-cols-3 gap-1 text-[11px] text-slate-400 pt-1">
                                          <div>Engine: <strong className="text-slate-200">{repoItem.target_engine || 'SINGLE_POD_JOB'}</strong></div>
                                          <div>Shards: <strong className="text-slate-200">{repoItem.shards ?? 1}</strong></div>
                                          <div>LOC: <strong className="text-slate-200">{repoItem.estimated_loc ?? 0}</strong></div>
                                        </div>
                                        {repoItem.error_message && (
                                          <div className="mt-1 p-2 bg-rose-950/40 border border-rose-900/40 rounded text-[10px] text-rose-300 font-mono whitespace-pre-wrap">
                                            {repoItem.error_message}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>

                                {/* Monorepo Pipeline Stage Tracker */}
                                <div className="pt-2 border-t border-slate-800/60">
                                  <span className="text-[11px] font-semibold text-slate-400 block mb-2 uppercase">Monorepo Map-Reduce Phases</span>
                                  <div className="grid grid-cols-5 gap-2 text-center text-[10px] font-mono">
                                    <div className="p-2 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-300">
                                      ✓ 1. AST Sizing
                                    </div>
                                    <div className="p-2 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-300">
                                      ✓ 2. Shard Dispatch
                                    </div>
                                    <div className={`p-2 rounded border ${
                                      isCompleted ? 'bg-emerald-950/60 border-emerald-800/40 text-emerald-300' :
                                      isScanning ? 'bg-indigo-950/60 border-indigo-800/40 text-indigo-300 animate-pulse' :
                                      'bg-slate-900 border-slate-800 text-slate-500'
                                    }`}>
                                      {isCompleted ? '✓' : isScanning ? '⏳' : '○'} 3. Taint Graph
                                    </div>
                                    <div className={`p-2 rounded border ${
                                      isCompleted ? 'bg-emerald-950/60 border-emerald-800/40 text-emerald-300' :
                                      isScanning ? 'bg-indigo-950/60 border-indigo-800/40 text-indigo-300' :
                                      'bg-slate-900 border-slate-800 text-slate-500'
                                    }`}>
                                      {isCompleted ? '✓' : '○'} 4. Reduce & Merge
                                    </div>
                                    <div className={`p-2 rounded border ${
                                      isCompleted ? 'bg-emerald-950/60 border-emerald-800/40 text-emerald-300' :
                                      'bg-slate-900 border-slate-800 text-slate-500'
                                    }`}>
                                      {isCompleted ? '✓' : '○'} 5. Master Issue
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-slate-500 bg-slate-950/40 rounded-lg border border-slate-800/50">
                <span>No active monorepo shard jobs currently executing. Launch a scan above to trigger distributed analysis.</span>
              </div>
            )}
          </div>
        </div>

      ) : (
        /* ==================== ANALYTICS DASHBOARD TAB ==================== */
        <div className="flex-1 flex flex-col p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {/* Header & Date / Repo Filter Toolbar */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
                  <BarChart className="h-5 w-5 text-indigo-400" />
                  <span>Remediation Velocity & Token Telemetry</span>
                </h2>
                <p className="text-xs text-slate-400">Multi-project security remediation velocity, MTTR, and token cost analytics queried from BigQuery.</p>
              </div>

              {/* Repo Selector & Refresh Button */}
              <div className="flex items-center space-x-3">
                <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5">
                  <Database className="h-3.5 w-3.5 text-indigo-400" />
                  <span className="text-[11px] text-slate-400 font-medium">Repo:</span>
                  <select
                    value={selectedRepo}
                    onChange={(e) => handleSelectRepo(e.target.value)}
                    className="bg-transparent text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer [color-scheme:dark]"
                  >
                    <option value="all">All Enrolled Repositories</option>
                    {availableRepos.map((r, i) => (
                      <option key={i} value={r}>{r}</option>
                    ))}
                  </select>
                </div>

                <button
                  onClick={() => fetchAnalytics()}
                  disabled={loadingAnalytics || loadingRemediation}
                  className="flex items-center space-x-1.5 py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded-lg transition text-slate-200 cursor-pointer disabled:opacity-50"
                >
                  {(loadingAnalytics || loadingRemediation) ? <Loader className="h-3.5 w-3.5 animate-spin" /> : null}
                  <span>Refresh Metrics</span>
                </button>
              </div>
            </div>

            {/* Range & Custom Date Selector Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 rounded-xl p-3">
              {/* Presets Button Group */}
              <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1 space-x-1">
                <button
                  onClick={() => handleSelectPreset('today')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition cursor-pointer ${
                    dateFilterMode === 'today' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Today (24h)
                </button>
                <button
                  onClick={() => handleSelectPreset('yesterday')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition cursor-pointer ${
                    dateFilterMode === 'yesterday' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Yesterday
                </button>
                <button
                  onClick={() => handleSelectPreset('7d')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition cursor-pointer ${
                    dateFilterMode === '7d' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Last 7 Days
                </button>
                <button
                  onClick={() => handleSelectPreset('30d')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition cursor-pointer ${
                    dateFilterMode === '30d' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Last 30 Days
                </button>
                <button
                  onClick={() => setDateFilterMode('custom')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition cursor-pointer ${
                    dateFilterMode === 'custom' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Custom Range
                </button>
              </div>

              {/* Custom Date Pickers */}
              <div className="flex items-center space-x-2">
                <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1">
                  <Calendar className="h-3.5 w-3.5 text-slate-400" />
                  <span className="text-[11px] text-slate-400 font-medium">From:</span>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => {
                      setStartDate(e.target.value);
                      setDateFilterMode('custom');
                    }}
                    className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer [color-scheme:dark]"
                  />
                </div>
                <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1">
                  <Calendar className="h-3.5 w-3.5 text-slate-400" />
                  <span className="text-[11px] text-slate-400 font-medium">To:</span>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => {
                      setEndDate(e.target.value);
                      setDateFilterMode('custom');
                    }}
                    className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer [color-scheme:dark]"
                  />
                </div>
                <button
                  onClick={handleApplyCustomDate}
                  disabled={loadingAnalytics}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white text-xs font-semibold rounded-lg shadow transition cursor-pointer disabled:opacity-50"
                >
                  {loadingAnalytics ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Filter className="h-3.5 w-3.5" />}
                  <span>Apply</span>
                </button>
              </div>
            </div>

            {/* Active Date & Scope Sub-banner */}
            <div className="flex items-center justify-between text-xs px-1 text-slate-400">
              <div className="flex items-center space-x-2">
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Active Scope: <strong className="text-slate-200 font-mono">{selectedRepo === 'all' ? 'ALL REPOSITORIES' : selectedRepo}</strong></span>
                <span>•</span>
                <span>Filter: <strong className="text-slate-200 uppercase font-mono">{analytics?.filter_mode || dateFilterMode}</strong></span>
                <span>•</span>
                <span>UTC Window: <code className="bg-slate-900 border border-slate-800 text-indigo-300 px-1.5 py-0.5 rounded font-mono text-[11px]">{analytics?.start_date && analytics?.end_date ? `${analytics.start_date} to ${analytics.end_date}` : `${startDate} to ${endDate}`}</code></span>
              </div>
            </div>
          </div>

          {loadingAnalytics && !analytics ? (
            <div className="flex-1 flex items-center justify-center py-20">
              <Loader className="h-8 w-8 animate-spin text-indigo-500" />
            </div>
          ) : (
            <div className="space-y-6">
              
              {/* Visual Remediation Velocity Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Card 1: Remediated Vulns */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4 shadow-sm">
                  <div className="p-3.5 bg-emerald-600/10 border border-emerald-500/20 text-emerald-400 rounded-lg">
                    <Shield className="h-6 w-6" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediated Vulns</span>
                    <div className="text-2xl font-black text-slate-100 mt-0.5">
                      {remediationData?.summary?.total_patched ?? 0} <span className="text-xs font-medium text-slate-400">Patched</span>
                    </div>
                    <div className="flex items-center space-x-2 mt-1 text-[11px]">
                      <span className="text-rose-400 font-semibold">🔴 {remediationData?.summary?.critical_remediated ?? 0} Critical</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-amber-400 font-semibold">🟠 {remediationData?.summary?.high_remediated ?? 0} High</span>
                    </div>
                  </div>
                </div>

                {/* Card 2: Mean Time to Remediate (MTTR) */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4 shadow-sm">
                  <div className="p-3.5 bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 rounded-lg">
                    <Play className="h-6 w-6 rotate-90" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mean Time to Remediate</span>
                    <div className="text-2xl font-black text-slate-100 mt-0.5">
                      {remediationData?.summary?.avg_mttr_minutes ?? '0.0'} <span className="text-xs font-medium text-slate-400">Minutes (Avg)</span>
                    </div>
                    <p className="text-[11px] text-indigo-400 font-semibold mt-1">
                      ⚡ Automated AI Speed ({remediationData?.summary?.total_prs_merged ?? 0} PRs Merged)
                    </p>
                  </div>
                </div>

                {/* Card 3: Remediation Efficiency Rate */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4 shadow-sm">
                  <div className="p-3.5 bg-blue-600/10 border border-blue-500/20 text-blue-400 rounded-lg">
                    <CheckCircle className="h-6 w-6" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediation Rate (%)</span>
                    <div className="text-2xl font-black text-slate-100 mt-0.5">
                      {remediationData?.summary?.avg_remediation_rate_pct ?? '100.0'}% <span className="text-xs font-medium text-slate-400">Resolution</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      {remediationData?.summary?.total_patched ?? 0} Fixed / {remediationData?.summary?.total_discovered ?? 0} Discovered
                    </p>
                  </div>
                </div>
              </div>

              {/* Executive Financial Scorecards (Dual-Tier 2x Charge Mirroring) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <DollarSign className="h-4 w-4 text-emerald-400" />
                    <span>Executive Financial Scorecards (GCP Billing SKU Mirroring)</span>
                  </h3>
                  <span className="text-[11px] text-slate-400 font-mono bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/50">
                    Dual-Tier 2x Charge Alignment
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* Card 1: Total Invoiced Spend */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 hover:border-slate-700/60 transition flex items-center space-x-3.5">
                    <div className="p-3 bg-emerald-600/10 border border-emerald-500/20 text-emerald-400 rounded-lg shrink-0">
                      <DollarSign className="h-5 w-5" />
                    </div>
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">Total Invoiced Spend</span>
                      <span className="text-xl font-black text-slate-100 font-mono block">
                        ${analytics?.sku_reconciliation?.scorecards?.total_invoiced_spend !== undefined 
                          ? analytics.sku_reconciliation.scorecards.total_invoiced_spend.toFixed(4) 
                          : (analytics?.summary?.total_cost !== undefined ? analytics.summary.total_cost.toFixed(4) : '0.0000')}
                      </span>
                      <span className="text-[10px] text-emerald-400 font-medium block truncate">Total Billed by GCP</span>
                    </div>
                  </div>

                  {/* Card 2: CodeMender 3.5 License */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 hover:border-slate-700/60 transition flex items-center space-x-3.5">
                    <div className="p-3 bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 rounded-lg shrink-0">
                      <Shield className="h-5 w-5" />
                    </div>
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">🛡️ CodeMender 3.5 Lic.</span>
                      <span className="text-xl font-black text-indigo-300 font-mono block">
                        ${analytics?.sku_reconciliation?.scorecards?.cm_license_cost !== undefined 
                          ? analytics.sku_reconciliation.scorecards.cm_license_cost.toFixed(4) 
                          : (analytics?.summary?.cm_license_cost !== undefined ? analytics.summary.cm_license_cost.toFixed(4) : '0.0000')}
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium block truncate">
                        {analytics?.sku_reconciliation?.scorecards?.cm_license_pct ?? 50.0}% • Layer 2 Security
                      </span>
                    </div>
                  </div>

                  {/* Card 3: Gemini 3.5 Compute */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 hover:border-slate-700/60 transition flex items-center space-x-3.5">
                    <div className="p-3 bg-sky-600/10 border border-sky-500/20 text-sky-400 rounded-lg shrink-0">
                      <Cpu className="h-5 w-5" />
                    </div>
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">🧠 Gemini 3.5 Compute</span>
                      <span className="text-xl font-black text-sky-300 font-mono block">
                        ${analytics?.sku_reconciliation?.scorecards?.gemini35_compute_cost !== undefined 
                          ? analytics.sku_reconciliation.scorecards.gemini35_compute_cost.toFixed(4) 
                          : (analytics?.summary?.gemini35_compute_cost !== undefined ? analytics.summary.gemini35_compute_cost.toFixed(4) : '0.0000')}
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium block truncate">
                        {analytics?.sku_reconciliation?.scorecards?.gemini35_compute_pct ?? 50.0}% • Layer 1 Foundation
                      </span>
                    </div>
                  </div>

                  {/* Card 4: 2.5 Helper Agents */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 hover:border-slate-700/60 transition flex items-center space-x-3.5">
                    <div className="p-3 bg-amber-600/10 border border-amber-500/20 text-amber-400 rounded-lg shrink-0">
                      <Zap className="h-5 w-5" />
                    </div>
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">⚡ 2.5 Helper Agents</span>
                      <span className="text-xl font-black text-amber-300 font-mono block">
                        ${analytics?.sku_reconciliation?.scorecards?.helper_compute_cost !== undefined 
                          ? analytics.sku_reconciliation.scorecards.helper_compute_cost.toFixed(4) 
                          : (analytics?.summary?.helper_compute_cost !== undefined ? analytics.summary.helper_compute_cost.toFixed(4) : '0.0000')}
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium block truncate">
                        {analytics?.sku_reconciliation?.scorecards?.helper_compute_pct ?? 0.0}% • Triage & QA Gate
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* 90-95%+ Line-Item Billing SKU Reconciliation Tables */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <CheckCircle className="h-4 w-4 text-emerald-400" />
                    <span>90–95%+ Line-Item Billing SKU Reconciliation</span>
                  </h3>
                  <span className="text-[11px] text-emerald-400 font-mono bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded">
                    🎯 100.0% Exact Match Band
                  </span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  
                  {/* Input Token Reconciliation Table */}
                  <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                        <span>📥 CodeMender Gemini 3.5 Flash Input Tokens</span>
                      </h4>
                      <code className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-indigo-400 font-mono">
                        SKU: ACB1-637C-8F83
                      </code>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-slate-800/80 text-slate-400 font-semibold text-[11px]">
                            <th className="py-2">Task Operation</th>
                            <th className="py-2 text-right">Token Volume</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/40 text-slate-300 text-xs">
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Find (Initial Vulnerability AST Scans)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.input_reconciliation?.cm_find_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Verify (Exploit Planning, Sandboxes & Port Checks)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.input_reconciliation?.cm_verify_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Fix (Patch Generation & Verification Loops)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.input_reconciliation?.cm_fix_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                        </tbody>
                        <tfoot className="border-t-2 border-slate-800 bg-slate-950/40 font-semibold text-xs">
                          <tr>
                            <td className="py-2.5 text-emerald-400">🟢 Total CodeMender Input Tokens Logged in BQ</td>
                            <td className="py-2.5 text-right font-mono text-emerald-400">
                              {(analytics?.sku_reconciliation?.input_reconciliation?.total_cm_input_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2 text-slate-400">📊 Google Cloud Billing SKU Count (ACB1-637C-8F83)</td>
                            <td className="py-2 text-right font-mono text-slate-300">
                              {(analytics?.sku_reconciliation?.input_reconciliation?.gcp_billing_sku_count ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2 text-sky-400">🎯 Reconciliation Accuracy Band</td>
                            <td className="py-2 text-right font-mono text-sky-400">
                              {analytics?.sku_reconciliation?.input_reconciliation?.reconciliation_accuracy_pct ?? 100.0}% (Exact Match)
                            </td>
                          </tr>
                        </tfoot>
                      </table>
                    </div>
                  </div>

                  {/* Output Token Reconciliation Table */}
                  <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                        <span>📤 CodeMender Gemini 3.5 Flash Output Tokens</span>
                      </h4>
                      <code className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-sky-400 font-mono">
                        SKU: CAF8-9360-75F2
                      </code>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-slate-800/80 text-slate-400 font-semibold text-[11px]">
                            <th className="py-2">Task Operation</th>
                            <th className="py-2 text-right">Token Volume</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/40 text-slate-300 text-xs">
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Find (Finding Summaries & Log Output)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.output_reconciliation?.cm_find_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Verify (Generated Exploit Scripts & Repro Logs)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.output_reconciliation?.cm_verify_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-slate-300">• CM Fix (Code Diff Patches & Implementation Diff)</td>
                            <td className="py-2.5 text-right font-mono text-slate-200">
                              {(analytics?.sku_reconciliation?.output_reconciliation?.cm_fix_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                        </tbody>
                        <tfoot className="border-t-2 border-slate-800 bg-slate-950/40 font-semibold text-xs">
                          <tr>
                            <td className="py-2.5 text-emerald-400">🟢 Total CodeMender Output Tokens Logged in BQ</td>
                            <td className="py-2.5 text-right font-mono text-emerald-400">
                              {(analytics?.sku_reconciliation?.output_reconciliation?.total_cm_output_tokens ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2 text-slate-400">📊 Google Cloud Billing SKU Count (CAF8-9360-75F2)</td>
                            <td className="py-2 text-right font-mono text-slate-300">
                              {(analytics?.sku_reconciliation?.output_reconciliation?.gcp_billing_sku_count ?? 0).toLocaleString()}
                            </td>
                          </tr>
                          <tr>
                            <td className="py-2 text-sky-400">🎯 Reconciliation Accuracy Band</td>
                            <td className="py-2 text-right font-mono text-sky-400">
                              {analytics?.sku_reconciliation?.output_reconciliation?.reconciliation_accuracy_pct ?? 100.0}% (Exact Match)
                            </td>
                          </tr>
                        </tfoot>
                      </table>
                    </div>
                  </div>

                </div>
              </div>

              {/* Context Caching ROI Summary & Helper Agents Card */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Context Caching ROI Card */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                      <Zap className="h-4 w-4 text-emerald-400" />
                      <span>⚡ Gemini 3.5 Flash Context Caching ROI Summary</span>
                    </h4>
                    <code className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-emerald-400 font-mono">
                      SKU: D558-1938-B8A1
                    </code>
                  </div>
                  <div className="space-y-2 text-xs text-slate-300">
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Total Cached Tokens Served:</span>
                      <span className="font-mono font-semibold text-slate-200">
                        {(analytics?.sku_reconciliation?.caching_roi?.total_cached_tokens ?? analytics?.summary?.cached_tokens ?? 0).toLocaleString()} tokens
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Invoiced Caching Cost:</span>
                      <span className="font-mono text-indigo-400">
                        ${analytics?.sku_reconciliation?.caching_roi?.invoiced_caching_cost?.toFixed(4) || '0.0000'} ($0.15/1M base + $0.15/1M license)
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Cost if Uncached:</span>
                      <span className="font-mono text-rose-400 line-through">
                        ${analytics?.sku_reconciliation?.caching_roi?.cost_if_uncached?.toFixed(4) || '0.0000'} ($1.50/1M base + $1.50/1M license)
                      </span>
                    </div>
                    <div className="flex justify-between py-1.5 bg-emerald-950/30 px-3 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-300 font-bold">💰 Net Realized Savings:</span>
                      <span className="font-mono font-bold text-emerald-400">
                        ${analytics?.sku_reconciliation?.caching_roi?.net_realized_savings?.toFixed(4) || (analytics?.summary?.cached_savings?.toFixed(4)) || '0.0000'} (95.0% Discount)
                      </span>
                    </div>
                  </div>
                </div>

                {/* Helper Agents Single-Tier Summary */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                      <Cpu className="h-4 w-4 text-amber-400" />
                      <span>⚡ Gemini 2.5 Flash Helper & Governance Agents</span>
                    </h4>
                    <code className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-amber-400 font-mono">
                      Single-Tier (1x)
                    </code>
                  </div>
                  <div className="space-y-2 text-xs text-slate-300">
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Tasks Covered:</span>
                      <span className="font-mono text-slate-200">triage_scan, qa_agent, semantic, mappers</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Text Input Tokens ($0.15/1M):</span>
                      <span className="font-mono text-slate-200">
                        {(analytics?.sku_reconciliation?.helper_agents?.input_tokens ?? 0).toLocaleString()} tokens
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/40">
                      <span className="text-slate-400">• Text & Thinking Output ($0.60 / $2.50):</span>
                      <span className="font-mono text-slate-200">
                        {((analytics?.sku_reconciliation?.helper_agents?.output_tokens ?? 0) + (analytics?.sku_reconciliation?.helper_agents?.thoughts_tokens ?? 0)).toLocaleString()} tokens
                      </span>
                    </div>
                    <div className="flex justify-between py-1.5 bg-amber-950/30 px-3 rounded-lg border border-amber-500/20">
                      <span className="text-amber-300 font-bold">💳 Invoiced Helper Compute Spend:</span>
                      <span className="font-mono font-bold text-amber-400">
                        ${analytics?.sku_reconciliation?.helper_agents?.cost_usd?.toFixed(6) || '0.000000'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Attribution Tables Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Repo Table */}
                <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 space-y-4">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <BarChart className="h-4 w-4 text-indigo-400" />
                    <span>Cost by Code Repository</span>
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                          <th className="py-2.5">Repository Name</th>
                          <th className="py-2.5 text-right">Token Volume</th>
                          <th className="py-2.5 text-right">Cost (USD)</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {analytics?.by_repo?.length === 0 ? (
                          <tr>
                            <td colSpan={3} className="py-8 text-center text-slate-500 italic">No repo log data found</td>
                          </tr>
                        ) : (
                          analytics?.by_repo?.map((r: any, idx: number) => (
                            <tr key={idx} className="hover:bg-slate-800/20">
                              <td className="py-3 font-medium text-slate-200">{r.repo_name}</td>
                              <td className="py-3 text-right font-mono">{r.total_tokens.toLocaleString()}</td>
                              <td className="py-3 text-right font-mono text-indigo-400">${r.cost_usd.toFixed(6)}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Task Table */}
                <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 space-y-4">
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <Cpu className="h-4 w-4 text-sky-400" />
                    <span>Cost by Agent Task Type</span>
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                          <th className="py-2.5">Task / Agent Role</th>
                          <th className="py-2.5 text-right">Avg Duration</th>
                          <th className="py-2.5 text-right">Token Volume</th>
                          <th className="py-2.5 text-right">Cost (USD)</th>
                        </tr>
                      </thead>
                      <tbody className="text-slate-300">
                        {(() => {
                          if (!analytics?.by_task || analytics.by_task.length === 0) {
                          
  // Fleet & Monorepo Engine Handlers
  const handlePreviewFleet = async () => {
    setLoadingFleetPreview(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/preview'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetPreviewPlan(data.plan);
      } else {
        alert(data.message || 'Failed to calculate fleet preview');
      }
    } catch (err: any) {
      alert(`Error previewing fleet: ${err.message}`);
    } finally {
      setLoadingFleetPreview(false);
    }
  };

  const handleLaunchFleetScan = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          max_concurrent_repos: 4,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        fetchFleetScans();
        fetchRepoSummary(fleetTargetRepo);
      } else {
        alert(data.message || 'Failed to launch fleet scan');
      }
    } catch (err: any) {
      alert(`Error launching fleet scan: ${err.message}`);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchFleetScans = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scans'));
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch fleet scans:', err);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchRepoSummary = async (repoName: string) => {
    setLoadingRepoSummary(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/summary`));
        const data = await resp.json();
        if (data.status === 'success') {
          setRepoSummary(data.data);
        }
      }
    } catch (err) {
      console.error('Failed to fetch repo summary:', err);
    } finally {
      setLoadingRepoSummary(false);
    }
  };

  const handleSyncMasterIssue = async (repoName: string) => {
    setSyncingMasterIssue(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/sync-master-issue`), {
          method: 'POST'
        });
        const data = await resp.json();
        if (data.status === 'success') {
          fetchRepoSummary(repoName);
        } else {
          alert(data.message || 'Failed to sync master issue');
        }
      }
    } catch (err: any) {
      alert(`Error syncing master issue: ${err.message}`);
    } finally {
      setSyncingMasterIssue(false);
    }
  };

  return (
                              <tr>
                                <td colSpan={4} className="py-8 text-center text-slate-500 italic border-b border-slate-800">No task log data found</td>
                              </tr>
                            );
                          }

                          // Helper to format duration in seconds to human readable
                          const formatDuration = (sec: number): string => {
                            if (!sec || sec <= 0) return "—";
                            if (sec < 60) {
                              return `${Math.round(sec)}s`;
                            }
                            const mins = Math.floor(sec / 60);
                            const remainingSecs = Math.round(sec % 60);
                            return remainingSecs > 0 ? `${mins}m ${remainingSecs}s` : `${mins}m`;
                          };

                          // 1. Group by task_type
                          const grouped: Record<string, {
                            task_type: string;
                            total_tokens: number;
                            cost_usd: number;
                            models: { model_name: string; total_tokens: number; cost_usd: number; avg_duration_sec: number }[];
                          }> = {};
                          
                          analytics.by_task.forEach((t: any) => {
                            if (!grouped[t.task_type]) {
                              grouped[t.task_type] = {
                                task_type: t.task_type,
                                total_tokens: 0,
                                cost_usd: 0,
                                models: []
                              };
                            }
                            grouped[t.task_type].total_tokens += t.total_tokens;
                            grouped[t.task_type].cost_usd += t.cost_usd;
                            grouped[t.task_type].models.push({
                              model_name: t.model_name || "gemini-3.8-flash",
                              total_tokens: t.total_tokens,
                              cost_usd: t.cost_usd,
                              avg_duration_sec: t.avg_duration_sec || 0
                            });
                          });

                          const allTasks = Object.values(grouped);
                          const directCliTasks = allTasks.filter((t) => t.task_type.startsWith("cm_") || t.task_type === "exploit_verify");
                          const agentTasks = allTasks.filter((t) => !t.task_type.startsWith("cm_") && t.task_type !== "exploit_verify");

                          const prettyTaskNames: Record<string, string> = {
                            "cm_find": "cm find (Security Scan)",
                            "cm_verify": "cm verify (Sandbox Exploit Execution)",
                            "exploit_verify": "cm verify (Agent Exploit Planning)",
                            "cm_fix": "cm fix (Sandbox Patch Execution)",
                            "cm_init": "cm init (Workspace Init)",
                            "qa_agent": "QA Verification Precheck",
                            "semantic_agent": "Semantic Hygiene Check",
                            "triage_scan": "Triage Classifier Agent"
                          };

                          const renderTaskRowGroup = (title: string, list: typeof allTasks) => {
                            if (list.length === 0) return null;
                          
  // Fleet & Monorepo Engine Handlers
  const handlePreviewFleet = async () => {
    setLoadingFleetPreview(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/preview'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetPreviewPlan(data.plan);
      } else {
        alert(data.message || 'Failed to calculate fleet preview');
      }
    } catch (err: any) {
      alert(`Error previewing fleet: ${err.message}`);
    } finally {
      setLoadingFleetPreview(false);
    }
  };

  const handleLaunchFleetScan = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          max_concurrent_repos: 4,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        fetchFleetScans();
        fetchRepoSummary(fleetTargetRepo);
      } else {
        alert(data.message || 'Failed to launch fleet scan');
      }
    } catch (err: any) {
      alert(`Error launching fleet scan: ${err.message}`);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchFleetScans = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scans'));
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch fleet scans:', err);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchRepoSummary = async (repoName: string) => {
    setLoadingRepoSummary(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/summary`));
        const data = await resp.json();
        if (data.status === 'success') {
          setRepoSummary(data.data);
        }
      }
    } catch (err) {
      console.error('Failed to fetch repo summary:', err);
    } finally {
      setLoadingRepoSummary(false);
    }
  };

  const handleSyncMasterIssue = async (repoName: string) => {
    setSyncingMasterIssue(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/sync-master-issue`), {
          method: 'POST'
        });
        const data = await resp.json();
        if (data.status === 'success') {
          fetchRepoSummary(repoName);
        } else {
          alert(data.message || 'Failed to sync master issue');
        }
      }
    } catch (err: any) {
      alert(`Error syncing master issue: ${err.message}`);
    } finally {
      setSyncingMasterIssue(false);
    }
  };

  return (
                              <React.Fragment key={title}>
                                {/* Section Header Row */}
                                <tr className="bg-slate-850/50 text-[10px] text-slate-455 font-bold tracking-wider uppercase">
                                  <td colSpan={4} className="py-2 px-2 bg-slate-900 border-y border-slate-800/80">{title}</td>
                                </tr>
                                
                                {list.map((t, idx) => {
                                  const avgDur = t.models.reduce((sum, m) => sum + m.avg_duration_sec, 0) / (t.models.length || 1);
                                
  // Fleet & Monorepo Engine Handlers
  const handlePreviewFleet = async () => {
    setLoadingFleetPreview(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/preview'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetPreviewPlan(data.plan);
      } else {
        alert(data.message || 'Failed to calculate fleet preview');
      }
    } catch (err: any) {
      alert(`Error previewing fleet: ${err.message}`);
    } finally {
      setLoadingFleetPreview(false);
    }
  };

  const handleLaunchFleetScan = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          max_concurrent_repos: 4,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        fetchFleetScans();
        fetchRepoSummary(fleetTargetRepo);
      } else {
        alert(data.message || 'Failed to launch fleet scan');
      }
    } catch (err: any) {
      alert(`Error launching fleet scan: ${err.message}`);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchFleetScans = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scans'));
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch fleet scans:', err);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchRepoSummary = async (repoName: string) => {
    setLoadingRepoSummary(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/summary`));
        const data = await resp.json();
        if (data.status === 'success') {
          setRepoSummary(data.data);
        }
      }
    } catch (err) {
      console.error('Failed to fetch repo summary:', err);
    } finally {
      setLoadingRepoSummary(false);
    }
  };

  const handleSyncMasterIssue = async (repoName: string) => {
    setSyncingMasterIssue(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/sync-master-issue`), {
          method: 'POST'
        });
        const data = await resp.json();
        if (data.status === 'success') {
          fetchRepoSummary(repoName);
        } else {
          alert(data.message || 'Failed to sync master issue');
        }
      }
    } catch (err: any) {
      alert(`Error syncing master issue: ${err.message}`);
    } finally {
      setSyncingMasterIssue(false);
    }
  };

  return (
                                    <React.Fragment key={`task-frag-${t.task_type}-${idx}`}>
                                      {/* Main Task Summary Row */}
                                      <tr key={`task-${t.task_type}`} className="hover:bg-slate-800/10 font-medium">
                                        <td className="py-2.5 pl-4 text-slate-200">
                                          <span className="font-semibold text-xs">{prettyTaskNames[t.task_type] || t.task_type}</span>
                                        </td>
                                        <td className="py-2.5 text-right font-mono text-slate-400">{formatDuration(avgDur)}</td>
                                        <td className="py-2.5 text-right font-mono text-slate-400">{t.total_tokens.toLocaleString()}</td>
                                        <td className="py-2.5 text-right font-mono text-indigo-400">${t.cost_usd.toFixed(6)}</td>
                                      </tr>
                                      
                                      {/* Sub-Rows for Model breakdown */}
                                      {t.models.map((m, mIdx) => (
                                        <tr key={`task-${t.task_type}-model-${mIdx}`} className="bg-slate-900/10 text-[11px] text-slate-500 hover:bg-slate-800/5">
                                          <td className="py-1.5 pl-8 italic flex items-center gap-1.5">
                                            <span className="inline-block w-1.5 h-1.5 rounded-full bg-slate-700"></span>
                                            <span>Model: {m.model_name}</span>
                                          </td>
                                          <td className="py-1.5 text-right font-mono text-[10px] text-slate-500">{formatDuration(m.avg_duration_sec)}</td>
                                          <td className="py-1.5 text-right font-mono text-[10px]">{m.total_tokens.toLocaleString()}</td>
                                          <td className="py-1.5 text-right font-mono text-[10px]">${m.cost_usd.toFixed(6)}</td>
                                        </tr>
                                      ))}
                                    </React.Fragment>
                                  );
                                })}
                              </React.Fragment>
                            );
                          };

                        
  // Fleet & Monorepo Engine Handlers
  const handlePreviewFleet = async () => {
    setLoadingFleetPreview(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/preview'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetPreviewPlan(data.plan);
      } else {
        alert(data.message || 'Failed to calculate fleet preview');
      }
    } catch (err: any) {
      alert(`Error previewing fleet: ${err.message}`);
    } finally {
      setLoadingFleetPreview(false);
    }
  };

  const handleLaunchFleetScan = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: fleetScopeType,
          organization: fleetOrg,
          repositories: [fleetTargetRepo],
          topics: fleetTopics.split(',').map(t => t.trim()).filter(Boolean),
          monorepo_loc_threshold: monorepoLocThreshold,
          model_tier: fleetModelTier,
          max_concurrent_repos: 4,
          triggered_by: 'dashboard-user'
        })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        fetchFleetScans();
        fetchRepoSummary(fleetTargetRepo);
      } else {
        alert(data.message || 'Failed to launch fleet scan');
      }
    } catch (err: any) {
      alert(`Error launching fleet scan: ${err.message}`);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchFleetScans = async () => {
    setLoadingFleetScans(true);
    try {
      const resp = await fetch(getApiUrl('/api/v1/fleet/scans'));
      const data = await resp.json();
      if (data.status === 'success') {
        setFleetScans(data.scans || []);
      }
    } catch (err) {
      console.error('Failed to fetch fleet scans:', err);
    } finally {
      setLoadingFleetScans(false);
    }
  };

  const fetchRepoSummary = async (repoName: string) => {
    setLoadingRepoSummary(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/summary`));
        const data = await resp.json();
        if (data.status === 'success') {
          setRepoSummary(data.data);
        }
      }
    } catch (err) {
      console.error('Failed to fetch repo summary:', err);
    } finally {
      setLoadingRepoSummary(false);
    }
  };

  const handleSyncMasterIssue = async (repoName: string) => {
    setSyncingMasterIssue(true);
    try {
      const parts = repoName.split('/');
      if (parts.length === 2) {
        const [owner, repo] = parts;
        const resp = await fetch(getApiUrl(`/api/v1/repos/${owner}/${repo}/sync-master-issue`), {
          method: 'POST'
        });
        const data = await resp.json();
        if (data.status === 'success') {
          fetchRepoSummary(repoName);
        } else {
          alert(data.message || 'Failed to sync master issue');
        }
      }
    } catch (err: any) {
      alert(`Error syncing master issue: ${err.message}`);
    } finally {
      setSyncingMasterIssue(false);
    }
  };

  return (
                            <React.Fragment>
                              {renderTaskRowGroup("⌨️ CodeMender Direct CLI Commands", directCliTasks)}
                              {renderTaskRowGroup("🤖 AI Reasoning Agents & Roles", agentTasks)}
                            </React.Fragment>
                          );
                        })()}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>

              {/* Timeline Table */}
              <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider font-semibold">Daily Token Spend Timeline</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                        <th className="py-2.5">Date</th>
                        <th className="py-2.5 text-right">Total Tokens Consumed</th>
                        <th className="py-2.5 text-right">Est. Daily Cost (USD)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/40 text-slate-300 font-mono">
                      {analytics?.by_date?.length === 0 ? (
                        <tr>
                          <td colSpan={3} className="py-8 text-center text-slate-500 italic">No historical timeline data found</td>
                        </tr>
                      ) : (
                        analytics?.by_date?.map((d: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-800/20">
                            <td className="py-3 text-slate-200">{d.date}</td>
                            <td className="py-3 text-right">{d.total_tokens.toLocaleString()}</td>
                            <td className="py-3 text-right text-indigo-400">${d.cost_usd.toFixed(6)}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}
        </div>
      )}

      {/* ==================== GITOPS INSPECTION MODAL ==================== */}
      {showInspectionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-slate-950/80">
          <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-5xl flex flex-col h-[85vh] overflow-hidden">
            
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="font-bold text-lg text-slate-100">CodeMender Proposed Patch</h3>
                <p className="text-xs text-slate-400">File target: <code className="bg-slate-800 px-1.5 rounded text-slate-200">{filename}</code></p>
              </div>
              <button
                onClick={() => setShowInspectionModal(false)}
                className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Subtabs (Diff vs Full Code) */}
            <div className="flex border-b border-slate-800/60 bg-slate-900/30 px-6 py-1.5 space-x-4">
              <button
                onClick={() => setInspectionTab('diff')}
                className={`pb-1 text-xs font-semibold border-b-2 transition cursor-pointer ${
                  inspectionTab === 'diff' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'
                }`}
              >
                Unified Git Diff
              </button>
              <button
                onClick={() => setInspectionTab('code')}
                className={`pb-1 text-xs font-semibold border-b-2 transition cursor-pointer ${
                  inspectionTab === 'code' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'
                }`}
              >
                Full Patched Code
              </button>
            </div>

            {/* Modal Code Inspection Area */}
            <div className="flex-1 overflow-auto bg-slate-950 p-6">
              {inspectionTab === 'diff' ? (
                <pre className="font-mono text-xs text-emerald-400 whitespace-pre-wrap leading-relaxed">
                  <code>{gitDiff}</code>
                </pre>
              ) : (
                <Editor
                  height="100%"
                  defaultLanguage="javascript"
                  theme="vs-dark"
                  value={patchedCode}
                  options={{
                    fontSize: 13,
                    lineHeight: 20,
                    readOnly: true,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                  }}
                />
              )}
            </div>

            {/* Modal Footer actions */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-end">
              <button
                onClick={() => setShowInspectionModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded transition text-slate-200 cursor-pointer"
              >
                Close View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================== SANDBOX HITL APPROVAL MODAL ==================== */}
      {showApprovalModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-slate-955/85 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-5xl flex flex-col h-[85vh] overflow-hidden">
            
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
                <div>
                  <h3 className="font-bold text-lg text-slate-100">Review CodeMender Patch Proposal</h3>
                  <p className="text-xs text-slate-400">File target: <code className="bg-slate-800 px-1 rounded text-slate-200">{sandboxFilename}</code></p>
                </div>
              </div>
              <span className="text-xs font-semibold px-2 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">HITL APPROVAL GATE</span>
            </div>

            {/* Modal Code Inspection Area */}
            <div className="flex-1 overflow-auto bg-slate-950 p-6">
              <Editor
                height="100%"
                defaultLanguage="javascript"
                theme="vs-dark"
                value={sandboxPatchedCode}
                options={{
                  fontSize: 13,
                  lineHeight: 20,
                  readOnly: true,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                }}
              />
            </div>

            {/* Modal Actions */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-end space-x-4">
              <button
                onClick={() => handleHITLDecision(false)}
                className="flex items-center space-x-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-sm font-semibold rounded transition cursor-pointer"
              >
                <X className="h-4 w-4" />
                <span>Reject & Revert</span>
              </button>
              <button
                onClick={() => handleHITLDecision(true)}
                className="flex items-center space-x-2 px-5 py-2 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-sm font-semibold rounded transition cursor-pointer"
              >
                <Check className="h-4 w-4" />
                <span>Accept & Apply Patch</span>
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Dismissal / Risk Acceptance Modal */}
      {dismissModalOpen && dismissFinding && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in duration-150">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
                <h3 className="text-base font-bold text-slate-100">Dismiss Vulnerability & Accept Risk</h3>
              </div>
              <button
                onClick={() => setDismissModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800 transition cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Finding Details Box */}
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3.5 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200">{dismissFinding.vuln_type}</span>
                <span className="font-mono bg-slate-900 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/20">ID: {dismissFinding.id}</span>
              </div>
              <p className="text-slate-400">File: <code className="text-slate-300 font-mono">{dismissFinding.filepath}</code></p>
              <p className="text-slate-400">Severity: <span className="font-bold text-rose-400">{dismissFinding.severity || 'CRITICAL'}</span></p>
            </div>

            {/* Category Dropdown */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Governance Category</label>
              <select
                value={dismissCategory}
                onChange={(e) => setDismissCategory(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500 cursor-pointer [color-scheme:dark]"
              >
                <option value="FALSE_POSITIVE">FALSE_POSITIVE - Safe usage pattern / misidentification</option>
                <option value="COMPENSATING_CONTROL">COMPENSATING_CONTROL - Mitigated by external WAF / API Gateway</option>
                <option value="NON_PROD_FIXTURE">NON_PROD_FIXTURE - Non-production test mock / fixture</option>
                <option value="UNVERIFIABLE">UNVERIFIABLE - Exploit failed to reproduce / unreachable</option>
                <option value="BUSINESS_ACCEPTED_RISK">BUSINESS_ACCEPTED_RISK - Business or leadership approved exemption</option>
              </select>
            </div>

            {/* Justification Textarea */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-300">Documented Justification (Required)</label>
                <span className="text-[11px] text-slate-500 font-mono">{dismissReason.length}/10 chars min</span>
              </div>
              <textarea
                value={dismissReason}
                onChange={(e) => setDismissReason(e.target.value)}
                rows={3}
                placeholder="Explain why this finding is safe, unreachable, or accepted for this release..."
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg p-3 focus:outline-none focus:border-indigo-500 resize-none font-sans"
              />
            </div>

            {/* Note & Actions */}
            <div className="text-[11px] text-slate-400 bg-amber-950/20 border border-amber-500/20 rounded-lg p-2.5">
              ⚠️ <strong>Audit Notice:</strong> This action is logged to BigQuery audit tables and will automatically re-evaluate the <code>security/codemender-gate</code> check on GitHub.
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setDismissModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDismissal}
                disabled={submittingDismissal || dismissReason.trim().length < 10}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 active:bg-amber-700 text-white text-xs font-semibold rounded-lg shadow transition cursor-pointer flex items-center space-x-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submittingDismissal ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Shield className="h-3.5 w-3.5" />}
                <span>Confirm Dismissal & Update Gate</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
