import React, { useState } from 'react';
import { Search, Globe, Calendar, UserCheck, ShieldCheck, Loader2, AlertCircle } from 'lucide-react';
import { queryDomainIntelligence } from '../services/api';

export default function DomainLookup() {
  const [domainInput, setDomainInput] = useState('');
  const [whoisResult, setWhoisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLookup = async (e) => {
    e.preventDefault();
    if (!domainInput.trim()) return;

    setLoading(true);
    setError(null);
    setWhoisResult(null);

    // Extract domain host if user pasted full URL
    let cleanDomain = domainInput.trim().toLowerCase();
    cleanDomain = cleanDomain.replace(/^(?:https?:\/\/)?(?:www\.)?/, '').split('/')[0].split('?')[0];

    try {
      const data = await queryDomainIntelligence(cleanDomain);
      setWhoisResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'WHOIS lookup failed or rate limited.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto py-8 px-4 animate-fadeIn space-y-8">
      
      {/* Header */}
      <div className="text-center">
        <h2 className="text-3xl font-black text-white mb-2 flex items-center justify-center gap-2">
          <Globe className="w-7 h-7 text-[#00f2fe]" />
          Domain WHOIS & Intelligence Tool
        </h2>
        <p className="text-xs text-gray-400 max-w-xl mx-auto">
          Query domain registration dates, domain age in days, registrar details, and privacy protection status.
        </p>
      </div>

      {/* Input */}
      <form onSubmit={handleLookup} className="max-w-2xl mx-auto">
        <div className="glass-card rounded-2xl p-2 border border-white/10 flex items-center gap-2">
          <Globe className="w-5 h-5 text-[#00f2fe] ml-3 shrink-0" />
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="Enter domain name (e.g. google.com, paypal.com)..."
            className="w-full bg-transparent text-white placeholder-gray-500 text-sm focus:outline-none py-2"
          />
          <button
            type="submit"
            disabled={loading || !domainInput.trim()}
            className="px-6 py-2.5 rounded-xl bg-[#00f2fe] text-black font-extrabold text-xs hover:brightness-110 disabled:opacity-40 transition-all shrink-0"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'LOOKUP'}
          </button>
        </div>
      </form>

      {error && (
        <div className="max-w-2xl mx-auto p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {whoisResult && (
        <div className="max-w-2xl mx-auto glass-card rounded-2xl p-6 border border-white/10 space-y-6">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <span className="text-[10px] text-gray-400 uppercase tracking-wider">DOMAIN HOST</span>
              <h3 className="text-xl font-bold text-cyan-300">{whoisResult.domain}</h3>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${
              whoisResult.is_recent ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            }`}>
              {whoisResult.is_recent ? 'RECENTLY REGISTERED (<90 days)' : 'ESTABLISHED DOMAIN'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-white/5 border border-white/5">
              <span className="text-xs text-gray-400 flex items-center gap-1.5 mb-1 font-medium">
                <Calendar className="w-4 h-4 text-[#00f2fe]" /> Creation Date
              </span>
              <div className="text-sm font-bold text-white">{whoisResult.creation_date || 'Hidden / Privacy Shield'}</div>
            </div>

            <div className="p-4 rounded-xl bg-white/5 border border-white/5">
              <span className="text-xs text-gray-400 flex items-center gap-1.5 mb-1 font-medium">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Domain Age
              </span>
              <div className="text-sm font-bold text-white">
                {whoisResult.age_days !== null ? `${whoisResult.age_days} days old` : 'Unknown'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-white/5 border border-white/5 sm:col-span-2">
              <span className="text-xs text-gray-400 flex items-center gap-1.5 mb-1 font-medium">
                <UserCheck className="w-4 h-4 text-purple-400" /> Registrar Details
              </span>
              <div className="text-sm font-bold text-white">{whoisResult.registrar || 'Privacy Protected'}</div>
            </div>
          </div>

          {whoisResult.error && (
            <p className="text-[11px] text-gray-500 italic">Notice: {whoisResult.error}</p>
          )}
        </div>
      )}

    </div>
  );
}
