export const BACKEND_URL = '';
export const PROXY_PREFIX = '/api/proxy';

export const API_ENDPOINTS = {
  HEALTH: '/health',
  CONFIG: '/config',
  NRD_LATEST: '/nrd-latest',
  BRAND_SEARCH: '/brand-search',
  DUMP_NRD: '/dump-nrd',
  // Monitoring endpoints
  MONITORING_GROUPS: '/monitoring/groups',
  MONITORING_GROUP: (id: string) => `/monitoring/groups/${id}`,
  MONITORING_GROUP_DOMAINS: (id: string) => `/monitoring/groups/${id}/domains`,
  MONITORING_FORCE_DUMP: (domainId: string) => `/monitoring/domains/${domainId}/force-dump`,
  MONITORING_DOMAIN_SNAPSHOTS: (domainId: string) => `/monitoring/domains/${domainId}/snapshots`,
  MONITORING_SNAPSHOT_DETAILS: (snapshotId: string) => `/monitoring/snapshots/${snapshotId}`,
  MONITORING_SNAPSHOT_SCREENSHOT: (snapshotId: string) => `/monitoring/snapshots/${snapshotId}/screenshot`,
  MONITORING_RESET: '/monitoring/reset',
};

export const getApiUrl = (endpoint: string): string => {
  return `${PROXY_PREFIX}${endpoint}`;
};

export const getAuthHeaders = (): Record<string, string> => {
  return {
    'Content-Type': 'application/json',
  };
};
