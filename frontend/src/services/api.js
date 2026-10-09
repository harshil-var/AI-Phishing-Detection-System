import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

export const scanUrl = async (url) => {
  const response = await api.post('/scan', { url });
  return response.data;
};

export const fetchRecentScans = async () => {
  const response = await api.get('/recent-scans');
  return response.data;
};

export const queryDomainIntelligence = async (domain) => {
  const response = await api.get(`/domain/${domain}`);
  return response.data;
};

export const sendSecurityChatMessage = async (prompt) => {
  const response = await api.post('/chat', { prompt });
  return response.data;
};

export const checkHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

export default api;
