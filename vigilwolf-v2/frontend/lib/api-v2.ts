interface ApiEnvelope<T> {
  data: T;
}

/** Retrieve the stored API key from localStorage (SSR-safe). */
function getApiKey(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("vigilwolf_api_key");
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const apiKey = getApiKey();
  const authHeaders: Record<string, string> = {};
  if (apiKey) {
    authHeaders["X-API-Key"] = apiKey;
  }

  const res = await fetch(`/api/v2${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders,
      ...options?.headers,
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${body || res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  const json = await res.json();
  if (json && typeof json === "object" && "data" in json) {
    return (json as ApiEnvelope<T>).data;
  }
  return json as T;
}

// ---------------------------------------------------------------------------
// Domain endpoints
// ---------------------------------------------------------------------------
export const domainsApi = {
  list: (params?: { cursor?: string; limit?: number; q?: string; risk_level?: string }) => {
    const qs = new URLSearchParams();
    if (params?.cursor) qs.set("cursor", params.cursor);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.q) qs.set("q", params.q);
    if (params?.risk_level) qs.set("risk_level", params.risk_level);
    const query = qs.toString();
    return apiFetch<{ items: DomainListItem[]; total: number; next_cursor?: string }>(
      `/domains${query ? `?${query}` : ""}`,
    );
  },

  get: async (id: string): Promise<Domain> => {
    const threat = await apiFetch<ThreatDetail>(`/domains/${id}/threat`);
    return {
      id: threat.domain.id,
      domain: threat.domain.url,
      status: threat.domain.active ? "active" : "inactive",
      risk_score: threat.risk_score?.total_score ?? 0,
      created_at: "",
      updated_at: "",
    };
  },

  scans: async (_id: string): Promise<Scan[]> => [],

  results: async (id: string): Promise<PluginResult[]> => {
    const threat = await apiFetch<ThreatDetail>(`/domains/${id}/threat`);
    return threat.analysis_results.map((r) => ({
      id: `${id}:${r.plugin_name}`,
      scan_id: id,
      plugin_name: r.plugin_name,
      severity: "medium",
      data: {
        score: r.score_contribution,
        confidence: r.confidence,
        tags: r.tags,
      },
      created_at: "",
    }));
  },

  /** Get threat feed — domains with risk scores */
  getThreats: (params?: {
    risk_level?: string;
    search?: string;
    cursor?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.risk_level) qs.set("risk_level", params.risk_level);
    if (params?.search) qs.set("q", params.search);
    if (params?.cursor) qs.set("cursor", params.cursor);
    if (params?.limit) qs.set("limit", String(params.limit));
    const query = qs.toString();
    return apiFetch<{ items: DomainListItem[]; total: number; next_cursor?: string }>(
      `/threats${query ? `?${query}` : ""}`,
    ).then((res) => ({
      ...res,
      items: res.items.map((d) => ({
        id: d.id,
        domain: d.url,
        risk_score: d.risk_score?.total_score ?? 0,
        severity: (d.risk_score?.severity as "high" | "medium" | "low") ?? "low",
        dominant_signals: d.risk_score?.dominant_signals ?? [],
        last_checked: "",
        created_at: "",
        updated_at: "",
      })),
    }));
  },

  /** Get threat statistics */
  getThreatStats: () => apiFetch<ThreatStats>("/threats/stats"),
};

// ---------------------------------------------------------------------------
// NRD (Newly Registered Domains) endpoints
// ---------------------------------------------------------------------------
export const nrdApi = {
  list: async () => {
    const res = await apiFetch<{ dumps: NRDDump[]; total: number }>("/nrd/latest");
    return { data: res.dumps, total: res.total };
  },

  search: (query: string, limit?: number) => {
    const qs = new URLSearchParams();
    qs.set("q", query);
    if (limit) qs.set("limit", String(limit));
    return apiFetch<{ results: Array<{ domain: string; source?: string }> }>(`/nrd/search?${qs.toString()}`)
      .then((r) =>
        r.results.map((item) => {
          const parts = item.domain.split(".");
          return {
            domain: item.domain,
            source: item.source,
            registered_at: new Date().toISOString(),
            tld: parts.length > 1 ? parts[parts.length - 1] : "",
            registrar: "unknown",
          };
        }),
      );
  },

  getStats: () => apiFetch<NRDStats>("/nrd/stats"),
};

// ---------------------------------------------------------------------------
// Monitor endpoints
// ---------------------------------------------------------------------------
export const monitorApi = {
  listGroups: () => apiFetch<MonitoringGroup[]>("/monitoring/groups"),

  getGroupDomains: (groupId: string) =>
    apiFetch<Array<{ id: string; url: string; active: boolean }>>(`/monitoring/groups/${groupId}/domains`).then((rows) =>
      rows.map((d) => ({
        id: d.id,
        domain: d.url,
        added_at: "",
        last_scan: null,
        risk_score: null,
      })),
    ),

  addDomain: (groupId: string, domain: string, frequencySeconds?: number) =>
    apiFetch<{
      id: string;
      url: string;
      group_id: string;
      frequency_seconds: number;
      active: boolean;
      created: boolean;
    }>(`/monitoring/groups/${groupId}/domains`, {
      method: "POST",
      body: JSON.stringify({
        domain,
        frequency_seconds: frequencySeconds ?? 3600,
      }),
    }).then((d) => ({
      id: d.id,
      domain: d.url,
      added_at: "",
      last_scan: null,
      risk_score: null,
    })),

  removeDomain: (groupId: string, domainId: string) =>
    apiFetch<void>(`/monitoring/groups/${groupId}/domains/${domainId}`, {
      method: "DELETE",
    }),

  createGroup: (data: { name: string; description?: string }) =>
    apiFetch<MonitoringGroup>("/monitoring/groups", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateGroup: (
    id: string,
    data: Partial<{ name: string; description: string }>,
  ) =>
    apiFetch<MonitoringGroup>(`/monitoring/groups/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  removeGroup: (id: string) =>
    apiFetch<void>(`/monitoring/groups/${id}`, { method: "DELETE" }),
};

// ---------------------------------------------------------------------------
// Webhook endpoints
// ---------------------------------------------------------------------------
export const webhooksApi = {
  list: () => apiFetch<Webhook[]>("/webhooks"),
  create: (data: CreateWebhook) =>
    apiFetch<Webhook>("/webhooks", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  update: (id: string, data: Partial<CreateWebhook>) =>
    apiFetch<Webhook>(`/webhooks/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  remove: (id: string) =>
    apiFetch<void>(`/webhooks/${id}`, { method: "DELETE" }),
  test: (id: string) =>
    apiFetch<{ success: boolean }>(`/webhooks/${id}/test`, { method: "POST" }).then((r) => ({
      ok: r.success,
    })),
};

// ---------------------------------------------------------------------------
// Alert endpoints
// ---------------------------------------------------------------------------
export const alertsApi = {
  list: (params?: { severity?: string; status?: string; cursor?: string }) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.status) qs.set("status", params.status);
    if (params?.cursor) qs.set("cursor", params.cursor);
    const query = qs.toString();
    return apiFetch<{ items: Alert[]; total: number; next_cursor?: string }>(
      `/alerts${query ? `?${query}` : ""}`,
    ).then((res) => ({
      ...res,
      items: res.items.map((a) => ({
        ...a,
        id: String(a.id),
        domain: a.domain_id ?? "unknown",
        acknowledged: a.acknowledged ?? false,
      })),
    }));
  },

  /** Acknowledge an alert */
  acknowledge: (id: string) =>
    apiFetch<Alert>(`/alerts/${id}/acknowledge`, { method: "POST" }),

  /** Retry a failed alert */
  retry: (id: string) =>
    apiFetch<Alert>(`/alerts/${id}/retry`, { method: "POST" }),
};

// ---------------------------------------------------------------------------
// Search endpoint
// ---------------------------------------------------------------------------
export const searchApi = {
  search: (query: string) =>
    apiFetch<{ results: SearchResult[] }>(
      `/search?q=${encodeURIComponent(query)}`
    ).then((r) => r.results),
};

// ---------------------------------------------------------------------------
// Plugin endpoints
// ---------------------------------------------------------------------------
export const pluginsApi = {
  list: () =>
    apiFetch<{ plugins: BackendPlugin[] }>("/plugins").then((r) =>
      r.plugins.map((p) => ({
        id: p.name,
        name: p.name,
        version: p.version,
        description: p.plugin_type,
        enabled: p.enabled,
        weight: p.weight,
        category: p.plugin_type,
      })),
    ),

  get: async (id: string) => {
    const plugins = await pluginsApi.list();
    const plugin = plugins.find((p) => p.id === id);
    if (!plugin) throw new Error(`Plugin ${id} not found`);
    return plugin;
  },

  toggle: (id: string, enabled: boolean) =>
    apiFetch<Plugin>(`/plugins/${id}/enabled`, {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    }),

  updateWeight: (id: string, weight: number) =>
    apiFetch<Plugin>(`/plugins/${id}/weight`, {
      method: "PUT",
      body: JSON.stringify({ weight }),
    }),
};

// ---------------------------------------------------------------------------
// Settings / Config endpoints
// ---------------------------------------------------------------------------
export const settingsApi = {
  getRiskThresholds: () =>
    apiFetch<{ risk_threshold_high: number; risk_threshold_medium: number }>("/risk-thresholds")
      .then((r) => ({ high: r.risk_threshold_high, medium: r.risk_threshold_medium })),

  getDryRunStatus: () =>
    Promise.resolve({ enabled: true }),
};

// ---------------------------------------------------------------------------
// Types — mirrors backend v2 models
// ---------------------------------------------------------------------------
export interface Domain {
  id: string;
  domain: string;
  status: string;
  risk_score: number;
  created_at: string;
  updated_at: string;
}
export interface DomainListItem {
  id: string;
  group_id: string;
  url: string;
  active: boolean;
  risk_level?: string;
  risk_score?: {
    total_score: number;
    normalized_score: number;
    risk_level: string;
    severity: string;
    reasons: string[];
    dominant_signals: string[];
    overall_confidence: number;
  };
}

export interface Scan {
  id: string;
  domain_id: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  results: PluginResult[];
}

export interface PluginResult {
  id: string;
  scan_id: string;
  plugin_name: string;
  severity: string;
  data: Record<string, unknown>;
  created_at: string;
}

export interface NRD {
  domain: string;
  source?: string;
  registered_at: string;
  tld: string;
  registrar: string;
}

export interface NRDDump {
  filename: string;
  date: string;
  domain_count: number;
  size: number;
  size_bytes: number;
  last_modified: string;
}

export interface NRDStats {
  total_domains: number;
  total_dumps: number;
  latest_dump: string | null;
  latest_dump_date: string | null;
}

export interface MonitoredDomain {
  id: string;
  domain: string;
  added_at: string;
  last_scan: string | null;
  risk_score: number | null;
}

export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  created_at: string;
}

export interface CreateWebhook {
  name: string;
  url: string;
  events: string[];
  enabled?: boolean;
}

export interface Alert {
  id: string | number;
  domain_id?: string;
  domain: string;
  event_type?: string;
  severity: string;
  title?: string;
  message?: string;
  acknowledged?: boolean;
  created_at: string;
  /** Delivery status for webhook alerts */
  status?: "sent" | "failed" | "retrying";
  webhook_name?: string;
}

export interface SearchResult {
  type: "domain" | "alert" | "threat" | string;
  id: string;
  title: string;
  description: string;
  score: number;
  url?: string;
  risk_level?: string;
}

export interface Plugin {
  id: string;
  name: string;
  version: string;
  description: string;
  enabled: boolean;
  weight: number;
  category: string;
}

// ---------------------------------------------------------------------------
// Threat types
// ---------------------------------------------------------------------------
export interface ThreatDomain {
  id: string;
  domain: string;
  risk_score: number;
  severity: "high" | "medium" | "low";
  dominant_signals: string[];
  last_checked: string;
  created_at: string;
  updated_at: string;
}

export interface ThreatStats {
  total: number;
  high: number;
  medium: number;
  low: number;
}

export interface MonitoringGroup {
  id: string;
  name: string;
  description?: string;
  domain_count: number;
  created_at?: string;
  updated_at?: string;
}

export interface RiskThresholds {
  high: number;
  medium: number;
}

interface BackendPlugin {
  name: string;
  version: string;
  plugin_type: string;
  weight: number;
  enabled: boolean;
}

interface ThreatDetail {
  domain: {
    id: string;
    url: string;
    active: boolean;
  };
  risk_score?: {
    total_score: number;
    severity: string;
  };
  analysis_results: Array<{
    plugin_name: string;
    score_contribution: number;
    confidence: number;
    tags: string[];
  }>;
}

// ---------------------------------------------------------------------------
// IOC types
// ---------------------------------------------------------------------------
export interface Ioc {
  id: number;
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
}

export interface IocDetail extends Ioc {
  occurrences: IocOccurrence[];
  relationships: IocRelationship[];
}

export interface IocOccurrence {
  id: number;
  snapshot_id: string;
  context: string | null;
  confidence: number;
  role: string | null;
  created_at: string;
}

export interface IocRelationship {
  id: number;
  source_ioc_id: number;
  target_ioc_id: number;
  relationship_type: string;
  confidence: number;
}

// ---------------------------------------------------------------------------
// Cluster types
// ---------------------------------------------------------------------------
export interface Cluster {
  id: string;
  cluster_type: string;
  signature_hash: string;
  description: string | null;
  domain_count: number;
  first_seen: string;
  last_seen: string;
}

export interface ClusterDetail extends Cluster {
  signature_type: string;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Campaign types
// ---------------------------------------------------------------------------
export interface Campaign {
  id: string;
  name: string;
  target_brand: string | null;
  status: string;
  domain_count: number;
  first_seen: string;
  last_seen: string;
}

export interface CampaignDetail extends Campaign {
  kit_signature: string | null;
  meta: Record<string, unknown>;
  clusters: Cluster[];
}

// ---------------------------------------------------------------------------
// Actor types
// ---------------------------------------------------------------------------
export interface Actor {
  id: string;
  label: string;
  confidence_score: number;
  first_seen: string;
  last_seen: string;
  campaign_count: number;
}

export interface ActorDetail extends Actor {
  fingerprint: Record<string, unknown>;
  meta: Record<string, unknown>;
  campaigns: Campaign[];
}

// ---------------------------------------------------------------------------
// IOC API
// ---------------------------------------------------------------------------
export const iocsApi = {
  list: (params?: { type?: string; q?: string; limit?: number; cursor?: string }) => {
    const qs = new URLSearchParams();
    if (params?.type) qs.set("type", params.type);
    if (params?.q) qs.set("q", params.q);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.cursor) qs.set("cursor", params.cursor);
    const query = qs.toString();
    return apiFetch<{ items: Ioc[]; next_cursor?: string }>(
      `/iocs${query ? `?${query}` : ""}`,
    );
  },

  get: (id: number) => apiFetch<IocDetail>(`/iocs/${id}`),

  getDomains: (id: number) =>
    apiFetch<{ items: Domain[] }>(`/iocs/${id}/domains`),
};

// ---------------------------------------------------------------------------
// Cluster API
// ---------------------------------------------------------------------------
export const clustersApi = {
  list: (params?: { cluster_type?: string; limit?: number; cursor?: string }) => {
    const qs = new URLSearchParams();
    if (params?.cluster_type) qs.set("cluster_type", params.cluster_type);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.cursor) qs.set("cursor", params.cursor);
    const query = qs.toString();
    return apiFetch<{ items: Cluster[]; next_cursor?: string }>(
      `/clusters${query ? `?${query}` : ""}`,
    );
  },

  get: (id: string) => apiFetch<ClusterDetail>(`/clusters/${id}`),

  getDomains: (id: string) =>
    apiFetch<{ items: (Domain & { confidence: number })[] }>(`/clusters/${id}/domains`),
};

// ---------------------------------------------------------------------------
// Campaign API
// ---------------------------------------------------------------------------
export const campaignsApi = {
  list: (params?: { status?: string; limit?: number; cursor?: string }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.cursor) qs.set("cursor", params.cursor);
    const query = qs.toString();
    return apiFetch<{ items: Campaign[]; next_cursor?: string }>(
      `/campaigns${query ? `?${query}` : ""}`,
    );
  },

  get: (id: string) => apiFetch<CampaignDetail>(`/campaigns/${id}`),

  update: (id: string, data: Partial<{ name: string; status: string; target_brand: string }>) =>
    apiFetch<CampaignDetail>(`/campaigns/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getDomains: (id: string) =>
    apiFetch<{ items: Domain[] }>(`/campaigns/${id}/domains`),
};

// ---------------------------------------------------------------------------
// Actor API
// ---------------------------------------------------------------------------
export const actorsApi = {
  list: (params?: { limit?: number; cursor?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.cursor) qs.set("cursor", params.cursor);
    const query = qs.toString();
    return apiFetch<{ items: Actor[]; next_cursor?: string }>(
      `/actors${query ? `?${query}` : ""}`,
    );
  },

  get: (id: string) => apiFetch<ActorDetail>(`/actors/${id}`),

  update: (id: string, data: Partial<{ label: string }>) =>
    apiFetch<ActorDetail>(`/actors/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getCampaigns: (id: string) =>
    apiFetch<{ items: Campaign[] }>(`/actors/${id}/campaigns`),
};