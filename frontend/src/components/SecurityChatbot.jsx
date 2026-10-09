import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, X, Shield, Sparkles, AlertCircle, User, Loader2 } from 'lucide-react';
import { sendSecurityChatMessage } from '../services/api';

const PRESET_QUERIES = [
  "How do I spot a phishing email?",
  "What should I do if I clicked a suspicious link?",
  "How does PhishGuard detect domain mismatch?",
  "Is HTTPS alone enough to trust a site?"
];

export default function SecurityChatbot({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    {
      sender: 'bot',
      text: "Hello! I'm PhishGuard AI, your dedicated cybersecurity assistant. Ask me anything about phishing, scam URLs, safe browsing habits, or online fraud prevention."
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  if (!isOpen) return null;

  const handleSend = async (textToSend) => {
    const promptText = textToSend || input;
    if (!promptText.trim() || loading) return;

    // Add user message
    const userMsg = { sender: 'user', text: promptText };
    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    try {
      const res = await sendSecurityChatMessage(promptText);
      setMessages((prev) => [
        ...prev,
        {
          sender: 'bot',
          text: res.response,
          topicBlocked: res.topic_blocked
        }
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'bot',
          text: "I am having trouble connecting to the Security AI service right now. Please ensure the backend is active.",
          topicBlocked: false
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-md bg-[#0a0f1d] border-l border-white/10 h-full flex flex-col shadow-2xl animate-slideLeft">
        
        {/* Header */}
        <div className="p-4 border-b border-white/10 bg-[#111827] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-[#00f2fe] to-purple-500 p-0.5 shadow-md shadow-cyan-500/20">
              <div className="w-full h-full bg-[#0a0f1d] rounded-[10px] flex items-center justify-center">
                <Bot className="w-5 h-5 text-[#00f2fe]" />
              </div>
            </div>
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                PhishGuard AI Assistant
                <span className="text-[9px] bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 px-1.5 py-0.5 rounded font-mono">GROQ</span>
              </h3>
              <p className="text-[10px] text-gray-400">Cybersecurity & Phishing Q&A Guard</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-white/5 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Message Log */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex items-start gap-2.5 ${msg.sender === 'user' ? 'flex-row-reverse' : ''}`}
            >
              <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                msg.sender === 'user' ? 'bg-cyan-500/20 text-cyan-300' : 'bg-purple-500/20 text-purple-300'
              }`}>
                {msg.sender === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              <div className={`max-w-[82%] p-3 rounded-2xl text-xs leading-relaxed ${
                msg.sender === 'user'
                  ? 'bg-gradient-to-r from-[#00f2fe] to-cyan-500 text-black font-medium rounded-tr-none'
                  : msg.topicBlocked
                  ? 'bg-amber-500/10 border border-amber-500/30 text-amber-200 rounded-tl-none'
                  : 'bg-[#111827] border border-white/10 text-gray-200 rounded-tl-none'
              }`}>
                {msg.topicBlocked && (
                  <div className="flex items-center gap-1.5 font-bold text-amber-400 mb-1 text-[11px]">
                    <AlertCircle className="w-3.5 h-3.5" />
                    <span>Topic Restricted:</span>
                  </div>
                )}
                {msg.text}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-2 text-xs text-gray-400 p-2">
              <Loader2 className="w-4 h-4 animate-spin text-[#00f2fe]" />
              <span>Analyzing security question...</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Preset Chips */}
        <div className="p-3 border-t border-white/5 bg-[#0e1424] flex gap-1.5 overflow-x-auto">
          {PRESET_QUERIES.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(q)}
              className="text-[10px] text-gray-300 bg-white/5 hover:bg-white/10 border border-white/10 px-2.5 py-1 rounded-full whitespace-nowrap transition-all"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="p-3 border-t border-white/10 bg-[#111827] flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about phishing, scam links, safe browsing..."
            className="flex-1 bg-[#0a0f1d] border border-white/10 rounded-xl px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-[#00f2fe]"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="p-2.5 rounded-xl bg-[#00f2fe] text-black font-bold hover:brightness-110 disabled:opacity-40 transition-all shrink-0"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

      </div>
    </div>
  );
}
