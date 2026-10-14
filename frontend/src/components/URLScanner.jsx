import React, { useState, useEffect } from 'react';
import { Search, ShieldAlert, Sparkles, Clipboard, ArrowRight, Loader2, RefreshCw } from 'lucide-react';

const SAMPLE_URLS = [
  { name: 'Safe Google', url: 'https://www.google.com', type: 'SAFE' },
  { name: 'Typosquatting Flipkart', url: 'https://f1ipkart.com', type: 'PHISHING' },
  { name: 'Subdomain Impersonation', url: 'https://flipkart.example.com', type: 'PHISHING' },
  { name: 'Phishing PayPal', url: 'http://paypal-verify-account-security-login.top/auth', type: 'PHISHING' },
  { name: 'IP Host Suspicious', url: 'http://192.168.1.1/account-update', type: 'SUSPICIOUS' },
  { name: 'Safe Flipkart', url: 'https://www.flipkart.com', type: 'SAFE' }
];

export default function URLScanner({ onScan, loading, error, onRetry, lastUrl }) {
  const [urlInput, setUrlInput] = useState('');
  const [validationWarning, setValidationWarning] = useState('');

  useEffect(() => {
    if (lastUrl && !urlInput) {
      setUrlInput(lastUrl);
    }
  }, [lastUrl]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setValidationWarning('');
    const trimmed = urlInput.trim();

    if (!trimmed) {
      setValidationWarning('Please enter a website URL to analyze.');
      return;
    }

    if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('file:')) {
      setValidationWarning(`Security restriction: Protocol scheme is not supported. Please enter a valid HTTP or HTTPS web address.`);
      return;
    }

    onScan(trimmed);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrlInput(text.trim());
        setValidationWarning('');
      }
    } catch (err) {
      console.warn('Clipboard read error:', err);
    }
  };

  const handleSampleClick = (sampleUrl) => {
    setUrlInput(sampleUrl);
    setValidationWarning('');
    onScan(sampleUrl);
  };

  return (
    <div className="w-full max-w-4xl mx-auto py-8 px-4">
      {/* Hero Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[#00f2fe] text-xs font-semibold mb-4">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Calibrated ML & Multi-Vector Threat Intelligence Engine</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-black text-white tracking-tight mb-4">
          AI-Powered <span className="bg-gradient-to-r from-[#00f2fe] via-cyan-300 to-emerald-400 bg-clip-text text-transparent">Phishing Detection</span> Platform
        </h1>
        <p className="text-gray-400 text-sm sm:text-base max-w-2xl mx-auto">
          Enter any URL to calculate risk scores, decision confidence, brand impersonation vectors, and Explainable AI (XAI) risk breakdowns.
        </p>
      </div>

      {/* Main URL Input Box */}
      <form onSubmit={handleSubmit} className="mb-4">
        <div className="relative glass-card rounded-2xl p-2 border border-white/10 shadow-2xl focus-within:border-[#00f2fe]/50 focus-within:shadow-[0_0_30px_rgba(0,242,254,0.15)] transition-all">
          <div className="flex items-center gap-3 px-3 py-2">
            <Search className="w-6 h-6 text-[#00f2fe] shrink-0" />
            
            <input
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (validationWarning) setValidationWarning('');
              }}
              placeholder="Paste or enter suspicious website URL (e.g., https://f1ipkart.com, paypal.com)..."
              className="w-full bg-transparent text-white placeholder-gray-500 text-sm sm:text-base focus:outline-none"
              disabled={loading}
            />

            {urlInput && (
              <button
                type="button"
                onClick={() => {
                  setUrlInput('');
                  setValidationWarning('');
                }}
                className="text-gray-500 hover:text-gray-300 text-xs px-2 py-1 rounded"
              >
                Clear
              </button>
            )}

            <button
              type="button"
              onClick={handlePaste}
              className="hidden sm:flex items-center gap-1 text-xs text-gray-400 hover:text-cyan-300 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 transition-all shrink-0"
              title="Paste from clipboard"
            >
              <Clipboard className="w-3.5 h-3.5" />
              <span>Paste</span>
            </button>

            <button
              type="submit"
              disabled={loading || !urlInput.trim()}
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black font-extrabold text-sm hover:brightness-110 active:scale-95 disabled:opacity-50 disabled:pointer-events-none shadow-lg shadow-cyan-500/25 transition-all shrink-0"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>ANALYZE URL</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Client validation warning */}
      {validationWarning && (
        <div className="mb-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{validationWarning}</span>
        </div>
      )}

      {/* Error alert with retry button */}
      {error && (
        <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <span className="font-bold">Scan Request Notice: </span>
              {error}
            </div>
          </div>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 text-xs font-semibold shrink-0 transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry</span>
            </button>
          )}
        </div>
      )}

      {/* Sample Test Links */}
      <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
        <span className="text-gray-500 font-medium mr-1">Benchmark Test Cases:</span>
        {SAMPLE_URLS.map((s, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleSampleClick(s.url)}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-all ${
              s.type === 'SAFE'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20'
                : s.type === 'PHISHING'
                ? 'bg-red-500/10 border-red-500/30 text-red-300 hover:bg-red-500/20'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20'
            }`}
          >
            {s.name}
          </button>
        ))}
      </div>
    </div>
  );
}
