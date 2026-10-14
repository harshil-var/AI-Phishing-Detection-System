import React, { useState, useEffect, useRef } from 'react';
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
  const [lastScannedUrl, setLastScannedUrl] = useState('');
  const [chatOpen, setChatOpen] = useState(false);

  // Counter to prevent stale responses from overwriting newer scans
  const scanSequence = useRef(0);

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
    const trimmed = urlToScan ? urlToScan.trim() : '';
    if (!trimmed) {
      setError('Please provide a valid URL string.');
      return;
    }

    const currentScanId = ++scanSequence.current;
    setLoading(true);
    setError(null);
    setLastScannedUrl(trimmed);
    // Clear previous scan results so stale data is not displayed during scan
    setScanData(null);

    try {
      const data = await scanUrl(trimmed);
      // Ensure only the latest scan updates the state
      if (currentScanId === scanSequence.current) {
        setScanData(data);
        setActiveTab('scanner');
      }
    } catch (err) {
      if (currentScanId === scanSequence.current) {
        let errorMsg = 'Failed to scan URL. Please verify backend server.';
        if (err.response?.data?.detail) {
          errorMsg = err.response.data.detail;
        } else if (err.code === 'ERR_NETWORK' || err.message?.includes('Network Error')) {
          errorMsg = 'Backend server is unreachable (port 8000). Ensure the FastAPI server is running.';
        } else if (err.message) {
          errorMsg = err.message;
        }
        setError(errorMsg);
      }
    } finally {
      if (currentScanId === scanSequence.current) {
        setLoading(false);
      }
    }
  };

  const handleRetry = () => {
    if (lastScannedUrl) {
      handleScan(lastScannedUrl);
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
              onRetry={handleRetry}
              lastUrl={lastScannedUrl}
            />
            {scanData && !loading && <ScanResults scanData={scanData} />}
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
