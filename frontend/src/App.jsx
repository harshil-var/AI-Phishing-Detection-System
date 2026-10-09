import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import URLScanner from './components/URLScanner';
import ScanResults from './components/ScanResults';
import SecurityChatbot from './components/SecurityChatbot';
import AnalyticsDashboard from './components/AnalyticsDashboard';
import DomainLookup from './components/DomainLookup';
import ExtensionGuide from './components/ExtensionGuide';
import Footer from './components/Footer';
import { scanUrl } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [chatOpen, setChatOpen] = useState(false);

  // Check URL query parameters for extension redirects (e.g. ?url=...)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlParam = params.get('url');
    const chatParam = params.get('chat');

    if (urlParam) {
      handleScan(decodeURIComponent(urlParam));
    }
    if (chatParam === 'open') {
      setChatOpen(true);
    }
  }, []);

  const handleScan = async (urlToScan) => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanUrl(urlToScan);
      setScanData(data);
      setActiveTab('scanner');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to scan URL. Please verify backend server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-between bg-[#0a0f1d] text-gray-100 selection:bg-[#00f2fe] selection:text-black">
      
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenChat={() => setChatOpen(true)}
      />

      {/* Main Content Body */}
      <main className="flex-1">
        {activeTab === 'scanner' && (
          <div className="space-y-4">
            <URLScanner
              onScan={handleScan}
              loading={loading}
              error={error}
            />
            {scanData && <ScanResults scanData={scanData} />}
          </div>
        )}

        {activeTab === 'analytics' && (
          <AnalyticsDashboard onRescan={handleScan} />
        )}

        {activeTab === 'domain' && (
          <DomainLookup />
        )}

        {activeTab === 'extension' && (
          <ExtensionGuide />
        )}
      </main>

      {/* Security Assistant AI Chatbot Drawer */}
      <SecurityChatbot
        isOpen={chatOpen}
        onClose={() => setChatOpen(false)}
      />

      {/* Footer */}
      <Footer />

    </div>
  );
}
