"use client";

import { useQuery, useInfiniteQuery } from "@tanstack/react-query";
import { useState, useCallback, useRef, useEffect } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ShieldAlert, TrendingUp, AlertTriangle, Info, Search, Loader2 } from "lucide-react";
import { domainsApi, type ThreatDomain, type ThreatStats } from "@/lib/api-v2";
import { VirtualizedTable } from "@/components/ui/virtualized-table";

const PAGE_SIZE = 50;

function severityColor(severity: string): string {
  switch (severity) {
    case "high":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "medium":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "low":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

function riskScoreColor(score: number): string {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-amber-400";
  return "text-green-400";
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <p className="text-sm text-zinc-500">{label}</p>
      </div>
      <p className={`mt-1 text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

const tableColumns = [
  {
    key: "domain",
    header: "Domain",
    className: "2fr",
    render: (threat: ThreatDomain) => (
      <Link
        href={`/threats/${threat.id}`}
        className="font-medium text-zinc-100 hover:text-red-400 hover:underline"
        onClick={(e) => e.stopPropagation()}
      >
        {threat.domain}
      </Link>
    ),
  },
  {
    key: "risk_score",
    header: "Risk Score",
    className: "100px",
    render: (threat: ThreatDomain) => (
      <span className={`font-mono font-semibold ${riskScoreColor(threat.risk_score)}`}>
        {threat.risk_score}
      </span>
    ),
  },
  {
    key: "severity",
    header: "Severity",
    className: "100px",
    render: (threat: ThreatDomain) => (
      <span
        className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${severityColor(threat.severity)}`}
      >
        {threat.severity.charAt(0).toUpperCase() + threat.severity.slice(1)}
      </span>
    ),
  },
  {
    key: "signals",
    header: "Signals",
    className: "1.5fr",
    render: (threat: ThreatDomain) => (
      <div className="flex flex-wrap gap-1">
        {threat.dominant_signals?.slice(0, 3).map((signal: string) => (
          <span
            key={signal}
            className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400"
          >
            {signal}
          </span>
        ))}
        {threat.dominant_signals?.length > 3 && (
          <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">
            +{threat.dominant_signals.length - 3}
          </span>
        )}
      </div>
    ),
  },
  {
    key: "last_checked",
    header: "Last Checked",
    className: "120px",
    render: (threat: ThreatDomain) => (
      <span className="text-zinc-500">
        {threat.last_checked
          ? formatDistanceToNow(new Date(threat.last_checked), { addSuffix: true })
          : "--"}
      </span>
    ),
  },
  {
    key: "actions",
    header: "",
    className: "80px",
    render: (threat: ThreatDomain) => (
      <Link
        href={`/threats/${threat.id}`}
        className="text-xs text-red-400 hover:underline"
        onClick={(e) => e.stopPropagation()}
      >
        View
      </Link>
    ),
  },
];

export default function ThreatsPage() {
  const [riskLevel, setRiskLevel] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    debounceTimerRef.current = setTimeout(() => {
      setDebouncedSearch(search);
    }, 300);
    return () => clearTimeout(debounceTimerRef.current);
  }, [search]);

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["threatStats"],
    queryFn: () => domainsApi.getThreatStats(),
  });

  const {
    data: threatsData,
    isLoading: threatsLoading,
    isFetchingNextPage,
    hasNextPage,
    fetchNextPage,
  } = useInfiniteQuery({
    queryKey: ["threats", riskLevel, debouncedSearch],
    queryFn: ({ pageParam }) =>
      domainsApi.getThreats({
        risk_level: riskLevel === "all" ? undefined : riskLevel,
        search: debouncedSearch || undefined,
        cursor: pageParam as string | undefined,
        limit: PAGE_SIZE,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const allThreats = threatsData?.pages.flatMap((page) => page.items) ?? [];
  const total = threatsData?.pages[0]?.total ?? 0;

  const loadMoreRef = useRef<HTMLDivElement>(null);
  const observerCallback = useCallback(
    (entries: IntersectionObserverEntry[]) => {
      const [entry] = entries;
      if (entry.isIntersecting && hasNextPage && !isFetchingNextPage) {
        fetchNextPage();
      }
    },
    [hasNextPage, isFetchingNextPage, fetchNextPage],
  );

  useEffect(() => {
    const el = loadMoreRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(observerCallback, {
      rootMargin: "200px",
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [observerCallback]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Threat Feed</h1>
        <p className="text-sm text-zinc-500">
          Domains ranked by risk score and detection signals
          {total > 0 && (
            <span className="ml-2 text-zinc-600">({total.toLocaleString()} total)</span>
          )}
        </p>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {statsLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-20 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))
        ) : (
          <>
            <StatCard
              label="Total Threats"
              value={stats?.total ?? 0}
              icon={ShieldAlert}
              color="text-zinc-100"
            />
            <StatCard
              label="High"
              value={stats?.high ?? 0}
              icon={AlertTriangle}
              color="text-red-400"
            />
            <StatCard
              label="Medium"
              value={stats?.medium ?? 0}
              icon={TrendingUp}
              color="text-amber-400"
            />
            <StatCard
              label="Low"
              value={stats?.low ?? 0}
              icon={Info}
              color="text-green-400"
            />
          </>
        )}
      </div>

      {/* Filter bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domains..."
            className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 pl-9 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          />
        </div>
        <select
          value={riskLevel}
          onChange={(e) => setRiskLevel(e.target.value)}
          className="h-9 rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          <option value="all">All Risk Levels</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Virtualized threat table */}
      <VirtualizedTable<ThreatDomain>
        columns={tableColumns}
        data={allThreats}
        rowKey={(t) => t.id}
        isLoading={threatsLoading}
        estimatedRowHeight={52}
        maxHeight="calc(100vh - 320px)"
        onRowClick={(t) => window.location.assign(`/threats/${t.id}`)}
        emptyContent={
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
            <ShieldAlert className="mx-auto h-8 w-8 text-zinc-600" />
            <p className="mt-2 text-sm text-zinc-500">
              No threats found matching your filters.
            </p>
          </div>
        }
        footer={
          <div ref={loadMoreRef} className="flex items-center justify-center py-3">
            {isFetchingNextPage && (
              <div className="flex items-center gap-2 text-sm text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading more...
              </div>
            )}
            {!hasNextPage && allThreats.length > 0 && (
              <p className="text-xs text-zinc-600">
                Showing {allThreats.length.toLocaleString()} of {total.toLocaleString()} threats
              </p>
            )}
          </div>
        }
      />
    </div>
  );
}