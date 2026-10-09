import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Activity, Bot, Puzzle, BarChart2, Search } from 'lucide-react';
import { checkHealth } from '../services/api';

export default function Navbar({ activeTab, setActiveTab, onOpenChat }) {
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    const verifyHealth = async () => {
      try {
        const data = await checkHealth();
        if (data.status === 'HEALTHY') setApiOnline(true);
      } catch (e) {
        setApiOnline(false);
      }
    };
    verifyHealth();
    const interval = setInterval(verifyHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-[#0a0f1d]/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand Logo */}
        <div 
          onClick={() => setActiveTab('scanner')} 
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#00f2fe] to-cyan-400 p-0.5 shadow-lg shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
            <div className="w-full h-full bg-[#0a0f1d] rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-[#00f2fe]" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg text-white tracking-wide">PhishGuard</span>
              <span className="bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black text-[10px] font-black px-1.5 py-0.5 rounded uppercase">
                AI PRO
              </span>
            </div>
            <p className="text-[11px] text-gray-400">Detection & Prevention System</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden md:flex items-center gap-1 bg-[#111827]/80 p-1.5 rounded-xl border border-white/5">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'scanner'
                ? 'bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black shadow-md shadow-cyan-500/20'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            URL Scanner
          </button>

          <button
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'analytics'
                ? 'bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black shadow-md shadow-cyan-500/20'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <BarChart2 className="w-3.5 h-3.5" />
            Analytics
          </button>

          <button
            onClick={() => setActiveTab('domain')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'domain'
                ? 'bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black shadow-md shadow-cyan-500/20'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Domain Lookup
          </button>

          <button
            onClick={() => setActiveTab('extension')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'extension'
                ? 'bg-gradient-to-r from-[#00f2fe] to-cyan-400 text-black shadow-md shadow-cyan-500/20'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Puzzle className="w-3.5 h-3.5" />
            Extension
          </button>
        </nav>

        {/* Right Action & API Status */}
        <div className="flex items-center gap-3">
          {/* API Health Pill */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#111827] border border-white/10 text-xs">
            <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
            <span className="text-gray-400 text-[11px] font-medium">
              {apiOnline ? 'FastAPI Online' : 'Connecting...'}
            </span>
          </div>

          {/* AI Security Assistant Button */}
          <button
            onClick={onOpenChat}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-purple-600/30 to-cyan-600/30 border border-cyan-500/30 text-cyan-300 hover:border-cyan-400 hover:text-white text-xs font-semibold transition-all shadow-lg shadow-cyan-500/10"
          >
            <Bot className="w-4 h-4 text-[#00f2fe]" />
            <span className="hidden sm:inline">AI Assistant</span>
          </button>
        </div>

      </div>
    </header>
  );
}
