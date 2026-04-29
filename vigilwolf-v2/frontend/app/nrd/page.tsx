"use client";

import { useQuery } from "@tanstack/react-query";
import { useState, useCallback } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  Globe,
  Database,
  Calendar,
  Search,
  RefreshCw,
  FileText,
} from "lucide-react";
import { nrdApi, type NRDStats, type NRDDump } from "@/lib/api-v2";

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function NRDPage() {
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  // Auto-refresh every 60s
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["nrdStats"],
    queryFn: () => nrdApi.getStats(),
    refetchInterval: 60000,
  });

  const { data: dumpsData, isLoading: dumpsLoading } = useQuery({
    queryKey: ["nrdDumps"],
    queryFn: () => nrdApi.list(),
    refetchInterval: 60000,
  });

  const { data: searchResults, isLoading: searchLoading } = useQuery({
    queryKey: ["nrdSearch", debouncedSearch],
    queryFn: () => nrdApi.search(debouncedSearch),
    enabled: debouncedSearch.length > 0,
  });

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearch(value);
      // Debounce search queries
      const timeout = setTimeout(() => {
        setDebouncedSearch(value);
      }, 300);
      return () => clearTimeout(timeout);
    },
    [],
  );

  const typedStats = stats as NRDStats | undefined;
  const dumps = (dumpsData as { data: NRDDump[] } | undefined)?.data ?? [];
  const isSearching = debouncedSearch.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">NRD Feed</h1>
          <p className="text-sm text-zinc-500">
            Browse newly registered domains
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-600">
          <RefreshCw className="h-3 w-3" />
          <span>Auto-refreshes every 60s</span>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {statsLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-20 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))
        ) : (
          <>
            <StatCard
              label="Total Domains"
              value={typedStats?.total_domains ?? 0}
              icon={Globe}
              color="text-zinc-100"
            />
            <StatCard
              label="Total Dumps"
              value={typedStats?.total_dumps ?? 0}
              icon={Database}
              color="text-red-400"
            />
            <StatCard
              label="Latest Dump"
              value={
                typedStats?.latest_dump_date
                  ? formatDistanceToNow(new Date(typedStats.latest_dump_date), {
                      addSuffix: true,
                    })
                  : "N/A"
              }
              icon={Calendar}
              color="text-amber-400"
            />
          </>
        )}
      </div>

      {/* Search bar */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search NRD dumps..."
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 pl-9 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        />
      </div>

      {/* Search results */}
      {isSearching ? (
        searchLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="h-12 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
              />
            ))}
          </div>
        ) : searchResults && searchResults.length > 0 ? (
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900/50">
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Domain
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Registered
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    TLD
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Registrar
                  </th>
                </tr>
              </thead>
              <tbody>
                {searchResults.map((nrd) => (
                  <tr
                    key={nrd.domain}
                    className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
                  >
                    <td className="px-4 py-3 font-medium text-zinc-100">
                      {nrd.domain}
                    </td>
                    <td className="px-4 py-3 text-zinc-500">
                      {formatDistanceToNow(new Date(nrd.registered_at), {
                        addSuffix: true,
                      })}
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
                        {nrd.tld}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-500">
                      {nrd.registrar}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
            <Search className="mx-auto h-8 w-8 text-zinc-600" />
            <p className="mt-2 text-sm text-zinc-500">
              No domains found matching &quot;{debouncedSearch}&quot;
            </p>
          </div>
        )
      ) : (
        /* Dumps table */
        dumpsLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div
                key={i}
                className="h-14 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
              />
            ))}
          </div>
        ) : dumps.length === 0 ? (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
            <FileText className="mx-auto h-8 w-8 text-zinc-600" />
            <p className="mt-2 text-sm text-zinc-500">
              No NRD dumps available yet. Dumps will appear here once ingested.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900/50">
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Filename
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Date
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Domain Count
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Size
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-zinc-400">
                    Last Modified
                  </th>
                </tr>
              </thead>
              <tbody>
                {dumps.map((dump: NRDDump) => (
                  <tr
                    key={dump.filename}
                    className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
                  >
                    <td className="px-4 py-3 font-medium text-zinc-100">
                      {dump.filename}
                    </td>
                    <td className="px-4 py-3 text-zinc-500">{dump.date}</td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-zinc-300">
                        {dump.domain_count.toLocaleString()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-500">
                      {formatBytes(dump.size)}
                    </td>
                    <td className="px-4 py-3 text-zinc-500">
                      {formatDistanceToNow(new Date(dump.last_modified), {
                        addSuffix: true,
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}