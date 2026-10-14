import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity, RefreshCw, ArrowUpRight, Info } from 'lucide-react';
import { fetchRecentScans } from '../services/api';

const COLORS = ['#10b981', '#f59e0b', '#ef4444'];

export default function AnalyticsDashboard({ onRescan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await fetchRecentScans();
      setScans(data || []);
    } catch (err) {
      console.warn('Failed to load recent scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const hasLiveTelemetry = scans.length > 0;

  // Real computation from live telemetry if available, else benchmark baseline
  const safeCount = scans.filter((s) => s.classification === 'SAFE').length;
  const suspCount = scans.filter((s) => s.classification === 'SUSPICIOUS').length;
  const phishCount = scans.filter((s) => s.classification === 'PHISHING').length;

  const pieData = hasLiveTelemetry
    ? [
        { name: 'SAFE', value: safeCount },
        { name: 'SUSPICIOUS', value: suspCount },
        { name: 'PHISHING', value: phishCount }
      ]
    : [
        { name: 'SAFE', value: 12 },
        { name: 'SUSPICIOUS', value: 5 },
        { name: 'PHISHING', value: 8 }
      ];

  const barData = hasLiveTelemetry
    ? [
        { name: 'Missing HTTPS', count: scans.filter(s => !s.security_checks?.https).length },
        { name: 'Login Keywords', count: scans.filter(s => s.security_checks?.suspicious_keywords).length },
        { name: 'Raw IP Host', count: scans.filter(s => s.security_checks?.ip_address).length },
        { name: 'Brand Mismatch', count: scans.filter(s => s.security_checks?.domain_mismatch).length },
        { name: 'Risky TLD', count: scans.filter(s => s.security_checks?.suspicious_tld).length }
      ]
    : [
        { name: 'Missing HTTPS', count: 4 },
        { name: 'Login Keywords', count: 7 },
        { name: 'Raw IP Host', count: 3 },
        { name: 'Brand Mismatch', count: 5 },
        { name: 'Risky TLD', count: 6 }
      ];

  const avgConfidence = hasLiveTelemetry
    ? (scans.reduce((acc, s) => acc + (s.confidence || 0), 0) / scans.length).toFixed(1)
    : '88.5';

  const threatRatio = hasLiveTelemetry
    ? Math.round((phishCount / scans.length) * 100)
    : 32;

  return (
    <div className="w-full max-w-6xl mx-auto py-6 px-4 animate-fadeIn space-y-8">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-[#00f2fe]" />
            Platform Threat Analytics
          </h2>
          <p className="text-xs text-gray-400">
            {hasLiveTelemetry
              ? `Real-time telemetry aggregated across ${scans.length} active scan(s).`
              : 'Aggregated detection telemetry and benchmark classification breakdown.'}
          </p>
        </div>

        <button
          onClick={loadHistory}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-gray-300 transition-all self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Data</span>
        </button>
      </div>

      {!hasLiveTelemetry && (
        <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs flex items-center gap-3">
          <Info className="w-4 h-4 shrink-0 text-[#00f2fe]" />
          <span>
            <b>Benchmark Demonstration Mode:</b> No scans logged yet in this backend session. The dashboard is displaying sample benchmark distributions. Scan URLs to generate real-time live telemetry!
          </span>
        </div>
      )}

      {/* Top Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-4 rounded-xl border border-white/10">
          <span className="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Total Scans Recorded</span>
          <div className="text-2xl font-black text-white mt-1">{scans.length}</div>
          <span className="text-[11px] text-cyan-400 font-mono">
            {hasLiveTelemetry ? 'Active Session Scans' : 'No Live Scans Yet'}
          </span>
        </div>

        <div className="glass-card p-4 rounded-xl border border-white/10">
          <span className="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Phishing Threat Ratio</span>
          <div className="text-2xl font-black text-red-400 mt-1">
            {threatRatio}%
          </div>
          <span className="text-[11px] text-red-400/80 font-mono">
            {hasLiveTelemetry ? `${phishCount} Flagged Phishing` : 'Baseline Benchmark'}
          </span>
        </div>

        <div className="glass-card p-4 rounded-xl border border-white/10">
          <span className="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Mean Decision Confidence</span>
          <div className="text-2xl font-black text-[#00f2fe] mt-1">{avgConfidence}%</div>
          <span className="text-[11px] text-emerald-400 font-mono">
            {hasLiveTelemetry ? 'Measured Session Certainty' : 'Trained Baseline Average'}
          </span>
        </div>

        <div className="glass-card p-4 rounded-xl border border-white/10">
          <span className="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Detection Pipeline</span>
          <div className="text-2xl font-black text-emerald-400 mt-1">OPERATIONAL</div>
          <span className="text-[11px] text-gray-400 font-mono">6 Modular Security Checkers</span>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Pie Chart */}
        <div className="glass-card p-6 rounded-2xl border border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white">Threat Classification Breakdown</h3>
            <span className="text-[10px] text-gray-400 font-mono">
              {hasLiveTelemetry ? 'Live Session Data' : 'Benchmark Sample'}
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 text-xs text-gray-300 font-medium mt-2">
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-emerald-500"></span> SAFE ({pieData[0].value})</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-amber-500"></span> SUSPICIOUS ({pieData[1].value})</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-red-500"></span> PHISHING ({pieData[2].value})</span>
          </div>
        </div>

        {/* Bar Chart */}
        <div className="glass-card p-6 rounded-2xl border border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white">Common Security Check Flags</h3>
            <span className="text-[10px] text-gray-400 font-mono">
              {hasLiveTelemetry ? 'Live Signals' : 'Benchmark Sample'}
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                <XAxis dataKey="name" stroke="#6b7280" fontSize={10} />
                <YAxis stroke="#6b7280" fontSize={10} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#00f2fe" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Recent Scans Table */}
      <div className="glass-card p-6 rounded-2xl border border-white/10">
        <h3 className="text-sm font-bold text-white mb-4">Recent Scan Log</h3>

        {scans.length === 0 ? (
          <div className="text-center py-8 text-xs text-gray-500">
            No scans recorded in current backend session. Use the URL Scanner to analyze links.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-[10px] text-gray-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3">URL</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-xs text-gray-300">
                {scans.map((s, idx) => (
                  <tr key={idx} className="hover:bg-white/5 transition-all">
                    <td className="py-3 px-3 max-w-xs truncate font-mono text-cyan-300" title={s.url}>
                      {s.url}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        s.classification === 'PHISHING'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : s.classification === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {s.classification}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-bold text-white">{s.risk_score}/100</td>
                    <td className="py-3 px-3 font-mono">{s.confidence}%</td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => onRescan(s.url)}
                        className="text-xs text-[#00f2fe] hover:underline flex items-center gap-1 justify-end ml-auto"
                      >
                        <span>Re-analyze</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
