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
import { Shield, Play, CheckCircle, XCircle, AlertTriangle, Loader, Check, X, Code, MessageSquare, Paperclip, BarChart, Database, Cpu, DollarSign, Calendar, RefreshCw } from 'lucide-react';

export default function Home() {
  const [activeTab, setActiveTab] = useState<'gitops' | 'sandbox' | 'analytics'>('gitops');
  
  // Sandbox state
  const [code, setCode] = useState<string>(`// Write or paste your vulnerable route code here...
const express = require('express');
const router = express.Router();
const db = require('../models');

router.get('/search', async (req, res) => {
  const query = req.query.q;
  // Vulnerable Query
  const results = await db.sequelize.query(
    \`SELECT * FROM Products WHERE name LIKE '%\${query}%'\`
  );
  res.json(results);
});
module.exports = router;`);
  
  const [intent, setIntent] = useState<string>('Fix the SQL injection vulnerability in the search route.');
  const [sessionId, setSessionId] = useState<string>('');
  const [logs, setLogs] = useState<{ timestamp: string; type: string; message: string }[]>([]);
  const [qaReport, setQaReport] = useState<{ matches_intent: boolean; feedback: string } | null>(null);
  const [semanticReport, setSemanticReport] = useState<{ has_secrets: boolean; hygiene_issues: string[] } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  
  // Dashboard state
  const [patches, setPatches] = useState<any[]>([]);
  const [loadingPatches, setLoadingPatches] = useState<boolean>(false);
  const [scans, setScans] = useState<any[]>([]);
  const [loadingScans, setLoadingScans] = useState<boolean>(false);

  // Analytics state
  const [analytics, setAnalytics] = useState<any>(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState<boolean>(false);
  const [rangeDays, setRangeDays] = useState<number>(7);
  const [dateFilterMode, setDateFilterMode] = useState<'today' | 'yesterday' | '7d' | '30d' | 'custom'>('7d');
  const [customStartDate, setCustomStartDate] = useState<string>(() => {
    const d = new Date();
    d.setDate(d.getDate() - 7);
    return d.toISOString().split('T')[0];
  });
  const [customEndDate, setCustomEndDate] = useState<string>(() => {
    return new Date().toISOString().split('T')[0];
  });

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

  // Finding Dismissal / Risk Acceptance Modal state
  const [dismissModalOpen, setDismissModalOpen] = useState<boolean>(false);
  const [dismissCommitSha, setDismissCommitSha] = useState<string>('');
  const [dismissFindingId, setDismissFindingId] = useState<string>('');
  const [dismissCategory, setDismissCategory] = useState<string>('FALSE_POSITIVE');
  const [dismissReason, setDismissReason] = useState<string>('');
  const [dismissLoading, setDismissLoading] = useState<boolean>(false);

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
        setScans(data.scans || []);
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

  const fetchAnalytics = async (mode = dateFilterMode, start = customStartDate, end = customEndDate) => {
    setLoadingAnalytics(true);
    try {
      let url = '/api/analytics/tokens';
      if (mode === 'today') {
        url += `?range_days=1`;
      } else if (mode === 'yesterday') {
        const d = new Date(Date.now() - 86400000);
        const yest = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
        url += `?start_date=${yest}&end_date=${yest}`;
      } else if (mode === 'custom') {
        url += `?start_date=${start}&end_date=${end}`;
      } else if (mode === '30d') {
        url += `?range_days=30`;
      } else {
        url += `?range_days=7`;
      }

      const response = await fetch(getApiUrl(url));
      const data = await response.json();
      if (data.status === 'success') {
        setAnalytics(data);
      }
    } catch (err) {
      console.error('Failed to fetch analytics:', err);
    } finally {
      setLoadingAnalytics(false);
    }
  };

  // Poll for patches and scans on mount
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Fetch analytics when analytics tab is opened and auto-refresh every 8 seconds
  useEffect(() => {
    if (activeTab === 'analytics') {
      fetchAnalytics(dateFilterMode, customStartDate, customEndDate);
      const interval = setInterval(() => {
        fetchAnalytics(dateFilterMode, customStartDate, customEndDate);
      }, 8000);
      return () => clearInterval(interval);
    }
  }, [activeTab, dateFilterMode, customStartDate, customEndDate]);


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

  const handleOpenDismissModal = (commitSha: string, findingId: string) => {
    setDismissCommitSha(commitSha);
    setDismissFindingId(findingId);
    setDismissCategory('FALSE_POSITIVE');
    setDismissReason('');
    setDismissModalOpen(true);
  };

  const handleConfirmDismiss = async () => {
    if (!dismissReason.trim() || dismissReason.trim().length < 5) {
      alert('Please enter a valid justification rationale (minimum 5 characters).');
      return;
    }
    setDismissLoading(true);
    try {
      const res = await fetch(getApiUrl(`/api/scans/${dismissCommitSha}/dismiss-finding`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: dismissFindingId,
          category: dismissCategory,
          reason: dismissReason.trim(),
          user: 'mgaur10'
        })
      });
      const data = await res.json();
      if (res.ok || data.status === 'accepted' || data.status === 'success') {
        setDismissModalOpen(false);
        fetchAllData();
      } else {
        alert(`Dismissal failed: ${data.message || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Network error: ${err.message}`);
    } finally {
      setDismissLoading(false);
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
                        <div className="flex items-center space-x-3">
                          {scan.pr_number ? (
                            <div className="flex items-center space-x-2">
                              {scan.pr_url ? (
                                <a
                                  href={scan.pr_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="font-bold text-indigo-400 hover:text-indigo-300 underline flex items-center space-x-1"
                                >
                                  <span>{scan.is_draft ? '📝 Draft PR' : '🚀 Pull Request'} #{scan.pr_number}</span>
                                </a>
                              ) : (
                                <span className="font-bold text-indigo-400">
                                  {scan.is_draft ? '📝 Draft PR' : '🚀 Pull Request'} #{scan.pr_number}
                                </span>
                              )}
                              <span className="text-slate-400 text-xs font-normal">({scan.branch_name})</span>
                            </div>
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
                        <div className="text-xs text-slate-400 flex items-center space-x-4">
                          <span>Head SHA: <code className="bg-slate-800 px-1.5 py-0.5 rounded font-mono text-[11px] text-slate-300">{scan.commit_sha?.substring(0, 7)}</code></span>
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
                            className="text-[10px] px-2 py-0.5 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/20 rounded cursor-pointer transition"
                          >
                            Cancel
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
                            <div key={fIdx} className="bg-slate-950/50 border border-slate-800/60 rounded-lg p-4 flex items-center justify-between space-x-4">
                              <div className="space-y-1">
                                <div className="flex items-center space-x-2">
                                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                                  <span className="font-bold text-sm text-slate-200">{finding.vuln_type}</span>
                                  <span className="text-[10px] font-mono bg-slate-900 text-slate-400 px-1.5 py-0.5 rounded">ID: {finding.id}</span>
                                </div>
                                <p className="text-xs text-slate-400">File: <code className="font-mono text-slate-300">{finding.filepath}</code></p>
                                {finding.description && <p className="text-xs text-slate-400">{finding.description}</p>}
                              </div>

                                <div className="flex items-center space-x-2">
                                  {/* Dismissed Status Badge */}
                                  {finding.status === 'DISMISSED' ? (
                                    <span className="text-xs text-amber-400 bg-amber-950/30 border border-amber-500/20 px-2.5 py-1 rounded font-semibold flex items-center space-x-1">
                                      <span>🟡 Dismissed ({finding.dismissal?.category || 'Risk Accepted'})</span>
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

                                      {/* Dismiss Action Button */}
                                      {finding.status !== 'PATCHED' && (
                                        <button
                                          onClick={() => handleOpenDismissModal(scan.commit_sha, finding.id)}
                                          className="py-1 px-2.5 bg-amber-600/10 hover:bg-amber-600/20 text-amber-400 border border-amber-500/20 text-xs font-semibold rounded transition cursor-pointer"
                                          title="Dismiss finding / accept risk"
                                        >
                                          Dismiss / Accept Risk
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
      ) : (
        /* ==================== ANALYTICS DASHBOARD TAB ==================== */
        <div className="flex-1 flex flex-col p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-100">Token Consumption & Cost Leadership</h2>
              <p className="text-xs text-slate-400">Real-time token cost and model consumption breakdown queried from BigQuery.</p>
            </div>
            
            {/* Range & Custom Date Selector */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-1 space-x-1">
                <button
                  onClick={() => {
                    setDateFilterMode('today');
                    fetchAnalytics('today');
                  }}
                  className={`px-3 py-1 text-xs font-semibold rounded transition cursor-pointer ${
                    dateFilterMode === 'today' ? 'bg-indigo-600 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Today (24h)
                </button>
                <button
                  onClick={() => {
                    setDateFilterMode('yesterday');
                    fetchAnalytics('yesterday');
                  }}
                  className={`px-3 py-1 text-xs font-semibold rounded transition cursor-pointer ${
                    dateFilterMode === 'yesterday' ? 'bg-indigo-600 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Yesterday
                </button>
                <button
                  onClick={() => {
                    setDateFilterMode('7d');
                    fetchAnalytics('7d');
                  }}
                  className={`px-3 py-1 text-xs font-semibold rounded transition cursor-pointer ${
                    dateFilterMode === '7d' ? 'bg-indigo-600 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  7 Days
                </button>
                <button
                  onClick={() => {
                    setDateFilterMode('30d');
                    fetchAnalytics('30d');
                  }}
                  className={`px-3 py-1 text-xs font-semibold rounded transition cursor-pointer ${
                    dateFilterMode === '30d' ? 'bg-indigo-600 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  30 Days
                </button>
                <button
                  onClick={() => setDateFilterMode('custom')}
                  className={`px-3 py-1 text-xs font-semibold rounded transition cursor-pointer ${
                    dateFilterMode === 'custom' ? 'bg-indigo-600 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Custom
                </button>
                <button
                  onClick={() => fetchAnalytics(dateFilterMode, customStartDate, customEndDate)}
                  disabled={loadingAnalytics}
                  className="flex items-center space-x-1.5 px-3 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-semibold rounded transition cursor-pointer disabled:opacity-50"
                  title="Refresh analytics telemetry metrics"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingAnalytics ? 'animate-spin text-indigo-400' : 'text-slate-400'}`} />
                  <span>Refresh</span>
                </button>
              </div>

              {/* Custom Date Pickers */}
              {dateFilterMode === 'custom' && (
                <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-1 space-x-2 text-xs text-slate-300">
                  <div className="flex items-center space-x-1.5 pl-1.5">
                    <Calendar className="w-3.5 h-3.5 text-indigo-400" />
                    <span className="text-slate-400">From:</span>
                    <input
                      type="date"
                      value={customStartDate}
                      onChange={(e) => setCustomStartDate(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <span className="text-slate-400">To:</span>
                    <input
                      type="date"
                      value={customEndDate}
                      onChange={(e) => setCustomEndDate(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <button
                    onClick={() => fetchAnalytics('custom', customStartDate, customEndDate)}
                    className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded text-xs transition cursor-pointer"
                  >
                    Apply
                  </button>
                </div>
              )}
            </div>
          </div>

          {loadingAnalytics && !analytics ? (
            <div className="flex-1 flex items-center justify-center py-20">
              <Loader className="h-8 w-8 animate-spin text-indigo-500" />
            </div>
          ) : (
            <div className="space-y-6">
              
              {/* Executive Metric Scorecards (Dual-Tier Breakdown) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                
                {/* Total Invoiced Cost */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4">
                  <div className="p-3.5 bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 rounded-lg shrink-0">
                    <DollarSign className="h-6 w-6" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">Total Invoiced Cost</span>
                    <span className="text-2xl font-black text-slate-100 font-mono block truncate">
                      ${analytics?.summary?.total_cost !== undefined ? analytics.summary.total_cost.toFixed(4) : '0.0000'}
                    </span>
                    <span className="text-[10px] text-slate-500 block truncate">
                      {analytics?.summary?.total_tokens?.toLocaleString() || 0} total tokens
                    </span>
                  </div>
                </div>

                {/* Vertex AI Compute */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4">
                  <div className="p-3.5 bg-sky-600/10 border border-sky-500/20 text-sky-400 rounded-lg shrink-0">
                    <Cpu className="h-6 w-6" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">Vertex AI Compute</span>
                    <span className="text-2xl font-black text-sky-300 font-mono block truncate">
                      ${analytics?.summary?.compute_cost !== undefined ? analytics.summary.compute_cost.toFixed(4) : '0.0000'}
                    </span>
                    <span className="text-[10px] text-slate-500 block truncate">
                      Layer 1 Foundation Model
                    </span>
                  </div>
                </div>

                {/* CodeMender License Fee */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4">
                  <div className="p-3.5 bg-purple-600/10 border border-purple-500/20 text-purple-400 rounded-lg shrink-0">
                    <Shield className="h-6 w-6" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">CodeMender License</span>
                    <span className="text-2xl font-black text-purple-300 font-mono block truncate">
                      ${analytics?.summary?.license_cost !== undefined ? analytics.summary.license_cost.toFixed(4) : '0.0000'}
                    </span>
                    <span className="text-[10px] text-slate-500 block truncate">
                      Layer 2 Security Solution
                    </span>
                  </div>
                </div>

                {/* Context Caching Savings */}
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 hover:border-slate-700/60 transition flex items-center space-x-4">
                  <div className="p-3.5 bg-emerald-600/10 border border-emerald-500/20 text-emerald-400 rounded-lg shrink-0">
                    <Database className="h-6 w-6" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <span className="text-[11px] font-semibold text-slate-400 block uppercase tracking-wider truncate">Context Cache Savings</span>
                    <span className="text-2xl font-black text-emerald-400 font-mono block truncate">
                      +${analytics?.summary?.cached_savings !== undefined ? analytics.summary.cached_savings.toFixed(4) : '0.0000'}
                    </span>
                    <span className="text-[10px] text-emerald-500/80 block truncate">
                      {analytics?.summary?.cached_tokens?.toLocaleString() || 0} cached tokens
                    </span>
                  </div>
                </div>

              </div>

              {/* Scanning Unit Economics ROI Suite */}
              <div className="bg-gradient-to-r from-slate-900/60 via-slate-900/40 to-slate-900/60 border border-slate-800/80 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-indigo-400 flex items-center space-x-2">
                    <BarChart className="w-4 h-4" />
                    <span>Scanning Unit Economics & Remediation ROI</span>
                  </h3>
                  <span className="text-[11px] text-slate-400 font-medium">
                    {analytics?.summary?.total_sessions || 0} Active Audit Sessions
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                  
                  {/* Cost per Scan */}
                  <div className="bg-slate-950/60 border border-slate-800/70 rounded-lg p-4 space-y-1">
                    <span className="text-[11px] font-semibold text-slate-400 block">Avg Cost Per Security Scan</span>
                    <div className="text-xl font-bold font-mono text-slate-200">
                      ${analytics?.summary?.avg_cost_per_scan !== undefined ? analytics.summary.avg_cost_per_scan.toFixed(4) : '0.0000'}
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Based on {analytics?.summary?.total_scans || 0} vulnerability scans
                    </span>
                  </div>

                  {/* Cost per Verified Vulnerability */}
                  <div className="bg-slate-950/60 border border-slate-800/70 rounded-lg p-4 space-y-1">
                    <span className="text-[11px] font-semibold text-slate-400 block">Avg Cost Per Exploit Verification</span>
                    <div className="text-xl font-bold font-mono text-slate-200">
                      ${analytics?.summary?.avg_cost_per_verified !== undefined ? analytics.summary.avg_cost_per_verified.toFixed(4) : '0.0000'}
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Based on {analytics?.summary?.total_verifications || 0} sandbox exploit runs
                    </span>
                  </div>

                  {/* Cost per Patch */}
                  <div className="bg-slate-950/60 border border-slate-800/70 rounded-lg p-4 space-y-1">
                    <span className="text-[11px] font-semibold text-slate-400 block">Avg Cost Per Remediated Patch</span>
                    <div className="text-xl font-bold font-mono text-emerald-400">
                      ${analytics?.summary?.avg_cost_per_patch !== undefined ? analytics.summary.avg_cost_per_patch.toFixed(4) : '0.0000'}
                    </div>
                    <span className="text-[10px] text-slate-500 block">
                      Based on {analytics?.summary?.total_patches || 0} autonomous patch PRs
                    </span>
                  </div>

                </div>
              </div>

              {/* GCP Billing & SKU Line-Item Reconciliation Table */}
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-purple-400 flex items-center space-x-2">
                      <Shield className="w-4 h-4 text-purple-400" />
                      <span>GCP Billing SKU Reconciliation & Line-Item Breakdown</span>
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      Bifurcated token metering matching Google Cloud Billing invoice line items (Gemini 3.5 Flash for CM Engine vs Gemini 2.5 Flash for Helpers).
                    </p>
                  </div>
                  <span className="text-[10px] font-mono bg-purple-950/40 border border-purple-500/30 text-purple-300 px-2 py-0.5 rounded font-semibold">
                    Dual-Tier 1:1 Invoiced Match
                  </span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-1">
                  
                  {/* Left: Input Tokens Reconciliation (ACB1-637C-8F83 / 9733-FF95-45E3) */}
                  <div className="bg-slate-950/60 border border-slate-800/70 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">📥 Input Tokens (cm find / verify / fix)</span>
                      <span className="text-[10px] font-mono text-slate-500">SKU: ACB1-637C-8F83 ($1.50/1M)</span>
                    </div>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Find (Vulnerability AST Scans):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_find_input || 0).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Verify (Sandbox Exploit Test Loops):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_verify_input || 0).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Fix (Patch Generation & Verification):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_fix_input || 0).toLocaleString()}</span>
                      </div>
                      <div className="border-t border-slate-800 pt-2 flex justify-between font-bold text-indigo-400">
                        <span>🟢 Total CodeMender Input Tokens (Gemini 3.5):</span>
                        <span className="font-mono text-indigo-300">{(analytics?.sku_reconciliation?.total_cm_input || 0).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  {/* Right: Output Tokens Reconciliation (CAF8-9360-75F2 / 4E73-15BD-0D78) */}
                  <div className="bg-slate-950/60 border border-slate-800/70 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">📤 Output Tokens (cm find / verify / fix)</span>
                      <span className="text-[10px] font-mono text-slate-500">SKU: CAF8-9360-75F2 ($9.00/1M)</span>
                    </div>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Find (Finding Summaries & Logs):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_find_output || 0).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Verify (Generated Exploit PoC Scripts):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_verify_output || 0).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>• CM Fix (Code Diff Patches & Diffs):</span>
                        <span className="font-mono text-slate-200">{(analytics?.sku_reconciliation?.cm_fix_output || 0).toLocaleString()}</span>
                      </div>
                      <div className="border-t border-slate-800 pt-2 flex justify-between font-bold text-sky-400">
                        <span>🟢 Total CodeMender Output Tokens (Gemini 3.5):</span>
                        <span className="font-mono text-sky-300">{(analytics?.sku_reconciliation?.total_cm_output || 0).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                </div>

                {/* Bottom Row: Context Caching & Helper Agents Breakdown */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                  
                  {/* Context Caching */}
                  <div className="bg-slate-950/40 border border-slate-800/60 rounded-lg p-3 flex items-center justify-between text-xs">
                    <div>
                      <span className="text-slate-400 font-medium block">⚡ Gemini 3.5 Context Caching (SKU: D558-1938-B8A1)</span>
                      <span className="text-[10px] text-slate-500">Invoiced at $0.15/1M base + $0.15/1M license</span>
                    </div>
                    <span className="font-mono font-bold text-emerald-400 text-sm">
                      {(analytics?.sku_reconciliation?.total_cm_cached || 0).toLocaleString()} tokens
                    </span>
                  </div>

                  {/* Helper Agents (Gemini 2.5 Flash) */}
                  <div className="bg-slate-950/40 border border-slate-800/60 rounded-lg p-3 flex items-center justify-between text-xs">
                    <div>
                      <span className="text-slate-400 font-medium block">🧠 Helper Agents (Gemini 2.5 Flash SKUs)</span>
                      <span className="text-[10px] text-slate-500">triage_scan, qa_agent, semantic_agent, exploit_formatter (1x Base Rate)</span>
                    </div>
                    <span className="font-mono font-bold text-purple-400 text-sm">
                      {((analytics?.sku_reconciliation?.helper_input || 0) + (analytics?.sku_reconciliation?.helper_output || 0) + (analytics?.sku_reconciliation?.helper_thoughts || 0)).toLocaleString()} tokens
                    </span>
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
                            models: Array<{ model_name: string; total_tokens: number; cost_usd: number; avg_duration_sec: number }>
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
                              model_name: t.model_name || "gemini-3.5-flash",
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
                            return (
                              <>
                                {/* Section Header Row */}
                                <tr className="bg-slate-850/50 text-[10px] text-slate-455 font-bold tracking-wider uppercase">
                                  <td colSpan={4} className="py-2 px-2 bg-slate-900 border-y border-slate-800/80">{title}</td>
                                </tr>
                                
                                {list.map((t, idx) => {
                                  const avgDur = t.models.reduce((sum, m) => sum + m.avg_duration_sec, 0) / (t.models.length || 1);
                                  return (
                                    <>
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
                                    </>
                                  );
                                })}
                              </>
                            );
                          };

                          return (
                            <>
                              {renderTaskRowGroup("⌨️ CodeMender Direct CLI Commands", directCliTasks)}
                              {renderTaskRowGroup("🤖 AI Reasoning Agents & Roles", agentTasks)}
                            </>
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

      {/* ==================== FINDING DISMISSAL / RISK ACCEPTANCE MODAL ==================== */}
      {dismissModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-amber-400 flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
                <span>Dismiss Finding / Accept Risk</span>
              </h3>
              <button
                onClick={() => setDismissModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-semibold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-sm">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                <div>
                  <span className="text-slate-400 text-xs">Finding ID:</span>{" "}
                  <code className="text-indigo-300 font-mono text-xs font-semibold">{dismissFindingId}</code>
                </div>
                <div>
                  <span className="text-slate-400 text-xs">Commit SHA:</span>{" "}
                  <code className="text-slate-300 font-mono text-xs">{dismissCommitSha.slice(0, 8)}</code>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1 text-xs">Exemption Category</label>
                <select
                  value={dismissCategory}
                  onChange={(e) => setDismissCategory(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500 text-xs"
                >
                  <option value="FALSE_POSITIVE">False Positive / Unreachable Pattern</option>
                  <option value="COMPENSATING_CONTROL">Compensating Control (WAF / Gateway / Network)</option>
                  <option value="NON_PROD_FIXTURE">Non-Production / Test Mock Fixture</option>
                  <option value="UNVERIFIABLE">Unverifiable / Sandbox Exploit Inconclusive</option>
                  <option value="BUSINESS_ACCEPTED_RISK">Documented Business Risk Exemption</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1 text-xs">
                  Justification Rationale <span className="text-red-400">*</span>
                </label>
                <textarea
                  value={dismissReason}
                  onChange={(e) => setDismissReason(e.target.value)}
                  placeholder="Explain why this finding is safe or exempt from blocking the merge gate (min 5 characters)..."
                  rows={3}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500 text-xs"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setDismissModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDismiss}
                disabled={dismissLoading || dismissReason.trim().length < 5}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition cursor-pointer flex items-center space-x-1.5"
              >
                {dismissLoading ? (
                  <>
                    <Loader className="h-3.5 w-3.5 animate-spin" />
                    <span>Applying Exemption...</span>
                  </>
                ) : (
                  <span>Confirm & Update Gate</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
