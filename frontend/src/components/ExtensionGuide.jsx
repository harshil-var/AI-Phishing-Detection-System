import React from 'react';
import { Puzzle, Download, CheckCircle2, Shield, Chrome, ArrowRight } from 'lucide-react';

export default function ExtensionGuide() {
  return (
    <div className="w-full max-w-4xl mx-auto py-8 px-4 animate-fadeIn space-y-8">
      {/* Header */}
      <div className="text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[#00f2fe] text-xs font-semibold mb-3">
          <Puzzle className="w-3.5 h-3.5" />
          <span>Chromium Extension Manifest V3</span>
        </div>
        <h2 className="text-3xl font-black text-white mb-2">
          Install PhishGuard Browser Extension
        </h2>
        <p className="text-xs text-gray-400 max-w-xl mx-auto">
          Get real-time warning overlays and instant popup risk scores automatically while browsing Google Chrome or Microsoft Edge.
        </p>
      </div>

      {/* Steps List */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-white/10 space-y-6">
        <h3 className="text-base font-bold text-white border-b border-white/10 pb-3 flex items-center gap-2">
          <Chrome className="w-5 h-5 text-[#00f2fe]" />
          Step-by-Step Unpacked Extension Installation Guide
        </h3>

        <div className="space-y-4 text-xs text-gray-300">
          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/5 border border-white/5">
            <span className="w-6 h-6 rounded-full bg-[#00f2fe] text-black font-extrabold flex items-center justify-center shrink-0">1</span>
            <div>
              <h4 className="font-bold text-white mb-1">Open Chrome / Edge Extensions Page</h4>
              <p className="text-gray-400">
                In your browser URL bar, navigate to <code className="text-cyan-300 bg-black/40 px-1.5 py-0.5 rounded font-mono">chrome://extensions</code> or <code className="text-cyan-300 bg-black/40 px-1.5 py-0.5 rounded font-mono">edge://extensions</code>.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/5 border border-white/5">
            <span className="w-6 h-6 rounded-full bg-[#00f2fe] text-black font-extrabold flex items-center justify-center shrink-0">2</span>
            <div>
              <h4 className="font-bold text-white mb-1">Enable Developer Mode</h4>
              <p className="text-gray-400">
                Toggle the <b className="text-white">Developer mode</b> switch located in the top-right corner of the Extensions page.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/5 border border-white/5">
            <span className="w-6 h-6 rounded-full bg-[#00f2fe] text-black font-extrabold flex items-center justify-center shrink-0">3</span>
            <div>
              <h4 className="font-bold text-white mb-1">Click "Load unpacked"</h4>
              <p className="text-gray-400">
                Click the <b className="text-white">Load unpacked</b> button at the top left of the Extensions dashboard.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/5 border border-white/5">
            <span className="w-6 h-6 rounded-full bg-[#00f2fe] text-black font-extrabold flex items-center justify-center shrink-0">4</span>
            <div>
              <h4 className="font-bold text-white mb-1">Select Project Extension Directory</h4>
              <p className="text-gray-400">
                Select the folder: <code className="text-cyan-300 bg-black/40 px-1.5 py-0.5 rounded font-mono">AI_Phishing_Detection_System/extension</code>
              </p>
            </div>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <div>
            <span className="font-bold">Active Protection Ready: </span>
            PhishGuard AI will now automatically analyze URLs in background tabs and display warning banners on suspicious sites!
          </div>
        </div>
      </div>
    </div>
  );
}
