export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

export const API_ENDPOINTS = {
  HEALTH: '/health',
  NRD_LATEST: '/nrd-latest',
  BRAND_SEARCH: '/brand-search',
  DUMP_NRD: '/dump-nrd',
};

export const getApiUrl = (endpoint: string): string => {
  return `${BACKEND_URL}${endpoint}`;
};
