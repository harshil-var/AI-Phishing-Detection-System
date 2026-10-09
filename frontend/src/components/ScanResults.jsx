import React, { useState } from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, Cpu, ExternalLink, 
  Lock, Key, Globe, Layers, AlertCircle, Info, Calendar, UserCheck, Flag, CheckCircle, XCircle 
} from 'lucide-react';

export default function ScanResults({ scanData }) {
  const [showReportModal, setShowReportModal] = useState(false);

  if (!scanData) return null;

  const {
    url,
    domain,
    classification,
    risk_score,
    confidence,
    severity,
    reasons = [],
    security_checks = {},
    whois_data = {}
  } = scanData;

  const isPhishing = classification === 'PHISHING';
  const isSuspicious = classification === 'SUSPICIOUS';
  const isSafe = classification === 'SAFE';

  // Badge Color configuration
  const statusColor = isPhishing
    ? 'text-red-400 bg-red-500/10 border-red-500/30'
    : isSuspicious
    ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
    : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';

  const riskColor = risk_score > 80
    ? '#ef4444'
    : risk_score > 60
    ? '#f97316'
    : risk_score > 30
    ? '#f59e0b'
    : '#10b981';

  const handleReportRedirect = () => {
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`;
    window.open(reportUrl, '_blank', 'noopener,noreferrer');
    setShowReportModal(false);
  };

  return (
    <div className="w-full max-w-5xl mx-auto py-6 px-4 animate-fadeIn">
      {/* Primary Result Banner Card */}
      <div className={`glass-card rounded-2xl p-6 sm:p-8 border mb-8 relative overflow-hidden ${
        isPhishing ? 'border-red-500/40 shadow-[0_0_50px_rgba(239,68,68,0.15)]' :
        isSuspicious ? 'border-amber-500/40 shadow-[0_0_50px_rgba(245,158,11,0.15)]' :
        'border-emerald-500/40 shadow-[0_0_50px_rgba(16,185,129,0.15)]'
      }`}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          
          {/* Status & URL */}
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-3">
              <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider border ${statusColor}`}>
                {isPhishing && <ShieldAlert className="w-4 h-4 text-red-400" />}
                {isSuspicious && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                {isSafe && <ShieldCheck className="w-4 h-4 text-emerald-400" />}
                <span>CLASSIFICATION: {classification}</span>
              </span>
              <span className="text-xs text-gray-400 font-mono">Severity: <b className="text-white">{severity}</b></span>
            </div>

            <h2 className="text-xl sm:text-2xl font-bold text-white break-all mb-2">
              {url}
            </h2>
            <p className="text-xs text-gray-400 flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-[#00f2fe]" />
              Domain Host: <span className="text-cyan-300 font-semibold">{domain}</span>
            </p>
          </div>

          {/* Gauges & Scores */}
          <div className="flex items-center gap-6 bg-[#0a0f1d]/70 p-4 rounded-xl border border-white/10 shrink-0">
            {/* Risk Score */}
            <div className="text-center">
              <div className="relative w-20 h-20 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-gray-800"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    strokeWidth="3.5"
                    strokeDasharray={`${risk_score}, 100`}
                    strokeLinecap="round"
                    stroke={riskColor}
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute text-center">
                  <span className="text-xl font-extrabold text-white">{risk_score}</span>
                  <span className="text-[9px] block text-gray-400 font-bold">/100</span>
                </div>
              </div>
              <span className="text-[11px] font-bold text-gray-300 uppercase tracking-wider block mt-1">Risk Score</span>
            </div>

            <div className="h-12 w-px bg-white/10"></div>

            {/* Confidence Score */}
            <div className="text-center">
              <div className="flex flex-col items-center justify-center h-20">
                <div className="flex items-baseline gap-0.5">
                  <span className="text-2xl font-black text-[#00f2fe]">{confidence}</span>
                  <span className="text-xs text-cyan-400 font-bold">%</span>
                </div>
                <div className="flex items-center gap-1 text-[10px] text-gray-400 mt-1">
                  <Cpu className="w-3 h-3 text-cyan-400" />
                  <span>ML Certainty</span>
                </div>
              </div>
              <span className="text-[11px] font-bold text-gray-300 uppercase tracking-wider block">Confidence</span>
            </div>
          </div>

        </div>
      </div>

      {/* Grid: Explainable AI & Security Checks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        
        {/* Explainable AI (XAI) Panel */}
        <div className="glass-card rounded-2xl p-6 border border-white/10">
          <div className="flex items-center justify-between mb-4 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-[#00f2fe]" />
              <h3 className="text-base font-bold text-white">Explainable AI (XAI) Analysis</h3>
            </div>
            <span className="text-[11px] bg-cyan-500/10 text-cyan-300 px-2 py-0.5 rounded font-mono">Interpretability Engine</span>
          </div>

          <p className="text-xs text-gray-400 mb-4">
            Why was this URL classified as <b className="text-white">{classification}</b> with a risk score of <b className="text-white">{risk_score}/100</b>?
          </p>

          <div className="space-y-3">
            {reasons.map((reason, idx) => (
              <div key={idx} className="flex items-start gap-3 p-3 rounded-xl bg-white/5 border border-white/5 text-xs text-gray-200">
                {isPhishing || isSuspicious ? (
                  <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                )}
                <span className="leading-relaxed">{reason}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Security Checks Grid */}
        <div className="glass-card rounded-2xl p-6 border border-white/10">
          <div className="flex items-center justify-between mb-4 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-base font-bold text-white">Modular Security Checks</h3>
            </div>
            <span className="text-[11px] bg-emerald-500/10 text-emerald-300 px-2 py-0.5 rounded font-mono">6 Verification Signals</span>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-4">
            
            {/* HTTPS */}
            <div className="p-3 rounded-xl bg-white/5 border border-white/5">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-400 flex items-center gap-1.5 font-medium">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" /> HTTPS Encryption
                </span>
                {security_checks.https ? (
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <XCircle className="w-3.5 h-3.5 text-red-400" />
                )}
              </div>
              <div className="text-xs font-bold text-white">
                {security_checks.https ? 'ENABLED (SSL/TLS)' : 'MISSING (HTTP Only)'}
              </div>
            </div>

            {/* Suspicious Keywords */}
            <div className="p-3 rounded-xl bg-white/5 border border-white/5">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-400 flex items-center gap-1.5 font-medium">
                  <Key className="w-3.5 h-3.5 text-amber-400" /> Login Keywords
                </span>
                {security_checks.suspicious_keywords ? (
                  <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                ) : (
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                )}
              </div>
              <div className="text-xs font-bold text-white">
                {security_checks.suspicious_keywords ? 'DETECTED' : 'CLEAN'}
              </div>
            </div>

            {/* IP Address Host */}
            <div className="p-3 rounded-xl bg-white/5 border border-white/5">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-400 flex items-center gap-1.5 font-medium">
                  <Globe className="w-3.5 h-3.5 text-cyan-400" /> Raw IP Usage
                </span>
                {security_checks.ip_address ? (
                  <XCircle className="w-3.5 h-3.5 text-red-400" />
                ) : (
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                )}
              </div>
              <div className="text-xs font-bold text-white">
                {security_checks.ip_address ? 'YES (Raw IP Host)' : 'NO (Domain Name)'}
              </div>
            </div>

            {/* Brand Impersonation */}
            <div className="p-3 rounded-xl bg-white/5 border border-white/5">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-400 flex items-center gap-1.5 font-medium">
                  <Layers className="w-3.5 h-3.5 text-purple-400" /> Brand Mismatch
                </span>
                {security_checks.domain_mismatch ? (
                  <XCircle className="w-3.5 h-3.5 text-red-400" />
                ) : (
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                )}
              </div>
              <div className="text-xs font-bold text-white">
                {security_checks.domain_mismatch ? 'MISMATCH DETECTED' : 'VERIFIED MATCH'}
              </div>
            </div>

          </div>

          {/* WHOIS Info Box */}
          <div className="p-3.5 rounded-xl bg-[#0a0f1d]/80 border border-white/10 text-xs">
            <div className="flex items-center justify-between text-gray-300 font-bold mb-2">
              <span className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-cyan-400" /> WHOIS Domain Intelligence
              </span>
              <span className="text-[10px] text-gray-500">{whois_data.status || 'CHECKED'}</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-gray-400">
              <div>
                <span>Domain Age: </span>
                <b className="text-white">
                  {whois_data.age_days !== null && whois_data.age_days !== undefined
                    ? `${whois_data.age_days} days`
                    : 'Unknown / Hidden'}
                </b>
              </div>
              <div>
                <span>Registrar: </span>
                <b className="text-white truncate block" title={whois_data.registrar || 'Hidden'}>
                  {whois_data.registrar || 'Privacy Protected'}
                </b>
              </div>
            </div>
          </div>

        </div>

      </div>

      {/* Action Footer Bar with Report Phishing Button */}
      <div className="glass-card rounded-2xl p-6 border border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h4 className="text-sm font-bold text-white flex items-center gap-2">
            <Info className="w-4 h-4 text-[#00f2fe]" />
            Found a dangerous phishing link?
          </h4>
          <p className="text-xs text-gray-400">
            Submit malicious links to Google Safe Browsing's official reporting mechanism to protect online users globally.
          </p>
        </div>

        <button
          onClick={() => setShowReportModal(true)}
          className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-extrabold text-xs tracking-wider uppercase shadow-lg shadow-red-600/20 transition-all shrink-0"
        >
          <Flag className="w-4 h-4" />
          <span>🚨 REPORT PHISHING LINK</span>
        </button>
      </div>

      {/* Confirmation Modal for Reporting */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="bg-[#111827] border border-red-500/40 rounded-2xl p-6 max-w-md w-full shadow-2xl animate-scaleIn">
            <div className="flex items-center gap-3 mb-4 text-red-400">
              <Flag className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Report Phishing to Google</h3>
            </div>
            
            <p className="text-xs text-gray-300 mb-4 leading-relaxed">
              You will be redirected to <b className="text-white">Google Safe Browsing's official reporting page</b> to submit the following link for global domain flagging:
            </p>

            <div className="p-3 rounded-lg bg-black/50 text-xs font-mono text-cyan-300 break-all mb-6 border border-white/10">
              {url}
            </div>

            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setShowReportModal(false)}
                className="px-4 py-2 rounded-lg text-xs font-semibold text-gray-400 hover:text-white hover:bg-white/5 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleReportRedirect}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold shadow-lg shadow-red-600/30 transition-all"
              >
                <span>Proceed to Google Reporting</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
