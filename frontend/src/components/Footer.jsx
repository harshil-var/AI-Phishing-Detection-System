import React from 'react';
import { Shield, Flag } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="w-full border-t border-white/10 bg-[#0a0f1d]/90 py-8 mt-16 text-xs text-gray-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
        
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#00f2fe]" />
          <span className="font-bold text-white">PhishGuard AI</span>
          <span>— Production AI Phishing Detection & Prevention Platform</span>
        </div>

        <div className="flex items-center gap-4 text-gray-500">
          <a
            href="https://safebrowsing.google.com/safebrowsing/report_phish/"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-red-400 flex items-center gap-1 transition-all"
          >
            <Flag className="w-3.5 h-3.5" />
            <span>Google Safe Browsing Reporting</span>
          </a>
        </div>

      </div>
    </footer>
  );
}
