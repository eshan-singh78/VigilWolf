"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowLeft, ExternalLink } from "lucide-react";
import {
  domainsApi,
  type Domain,
  type PluginResult,
} from "@/lib/api-v2";

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

function scoreBarColor(score: number): string {
  if (score >= 70) return "bg-red-500";
  if (score >= 40) return "bg-amber-500";
  return "bg-green-500";
}

export default function ThreatDetailPage() {
  const params = useParams();
  const router = useRouter();
  const domainId = params.domainId as string;

  const { data: domain, isLoading: domainLoading } = useQuery({
    queryKey: ["domain", domainId],
    queryFn: () => domainsApi.get(domainId),
  });

  const { data: results, isLoading: resultsLoading } = useQuery({
    queryKey: ["domainResults", domainId],
    queryFn: () => domainsApi.results(domainId),
  });

  if (domainLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 animate-pulse rounded bg-zinc-800" />
        <div className="h-40 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
      </div>
    );
  }

  if (!domain) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-500">Domain not found.</p>
        <Link
          href="/threats"
          className="mt-2 text-sm text-red-400 hover:underline"
        >
          Back to Threats
        </Link>
      </div>
    );
  }

  const d = domain as Domain;
  const severity =
    d.risk_score >= 70 ? "high" : d.risk_score >= 40 ? "medium" : "low";

  return (
    <div className="space-y-6">
      {/* Back nav */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Threats
      </button>

      {/* Domain info card */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">{d.domain}</h1>
            <div className="mt-2 flex items-center gap-3">
              <span
                className={`font-mono text-3xl font-bold ${riskScoreColor(d.risk_score)}`}
              >
                {d.risk_score}
              </span>
              <span
                className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-medium ${severityColor(severity)}`}
              >
                {severity.charAt(0).toUpperCase() + severity.slice(1)}
              </span>
            </div>
          </div>
          <a
            href={d.domain.startsWith("http") ? d.domain : `https://${d.domain}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition-colors hover:bg-zinc-800 hover:text-zinc-100"
          >
            Open Domain
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </div>

      {/* Score breakdown */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h2 className="mb-4 text-lg font-semibold text-zinc-100">
          Score Breakdown
        </h2>
        {resultsLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="h-8 animate-pulse rounded bg-zinc-800"
              />
            ))}
          </div>
        ) : results && results.length > 0 ? (
          <div className="space-y-3">
            {results.map((r: PluginResult) => {
              const score =
                typeof r.data === "object" && r.data !== null && "score" in r.data
                  ? Number(r.data.score)
                  : 0;
              return (
                <div key={r.id} className="flex items-center gap-3">
                  <span className="w-32 shrink-0 truncate text-sm text-zinc-400">
                    {r.plugin_name}
                  </span>
                  <div className="flex-1">
                    <div className="h-2.5 w-full rounded-full bg-zinc-800">
                      <div
                        className={`h-2.5 rounded-full ${scoreBarColor(score)}`}
                        style={{ width: `${Math.min(score, 100)}%` }}
                      />
                    </div>
                  </div>
                  <span className="w-10 text-right font-mono text-sm text-zinc-400">
                    {score}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-zinc-500">
            No plugin results available yet.
          </p>
        )}
      </div>

      {/* Analysis results table */}
      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="px-4 py-3 text-left font-medium text-zinc-400">
                Plugin
              </th>
              <th className="px-4 py-3 text-left font-medium text-zinc-400">
                Score
              </th>
              <th className="px-4 py-3 text-left font-medium text-zinc-400">
                Confidence
              </th>
              <th className="px-4 py-3 text-left font-medium text-zinc-400">
                Tags
              </th>
            </tr>
          </thead>
          <tbody>
            {resultsLoading ? (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-6 text-center text-zinc-500"
                >
                  Loading...
                </td>
              </tr>
            ) : results && results.length > 0 ? (
              results.map((r: PluginResult) => {
                const data = r.data as Record<string, unknown>;
                const score = "score" in data ? Number(data.score) : null;
                const confidence =
                  "confidence" in data ? Number(data.confidence) : null;
                const tags =
                  "tags" in data && Array.isArray(data.tags)
                    ? (data.tags as string[])
                    : [];
                return (
                  <tr
                    key={r.id}
                    className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
                  >
                    <td className="px-4 py-3 font-medium text-zinc-200">
                      {r.plugin_name}
                    </td>
                    <td className="px-4 py-3">
                      {score !== null ? (
                        <span
                          className={`font-mono ${riskScoreColor(score)}`}
                        >
                          {score}
                        </span>
                      ) : (
                        <span className="text-zinc-600">--</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {confidence !== null ? (
                        <span className="font-mono text-zinc-400">
                          {confidence}%
                        </span>
                      ) : (
                        <span className="text-zinc-600">--</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {tags.map((tag: string) => (
                          <span
                            key={tag}
                            className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-6 text-center text-zinc-500"
                >
                  No analysis results yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Recent snapshots */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h2 className="mb-4 text-lg font-semibold text-zinc-100">
          Recent Snapshots
        </h2>
        {d.updated_at ? (
          <div className="space-y-2 text-sm text-zinc-400">
            <p>
              Last scanned:{" "}
              {formatDistanceToNow(new Date(d.updated_at), {
                addSuffix: true,
              })}
            </p>
            <p>
              First seen:{" "}
              {formatDistanceToNow(new Date(d.created_at), {
                addSuffix: true,
              })}
            </p>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No scan data available.</p>
        )}
      </div>
    </div>
  );
}