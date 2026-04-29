"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { Boxes, Search } from "lucide-react";
import { clustersApi, type Cluster } from "@/lib/api-v2";

function clusterTypeColor(type: string): string {
  switch (type) {
    case "html_similarity":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "infra":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "phishkit":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "campaign":
      return "bg-purple-500/20 text-purple-400 border-purple-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function ClustersPage() {
  const [clusterType, setClusterType] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["clusters", clusterType],
    queryFn: () =>
      clustersApi.list({
        cluster_type: clusterType === "all" ? undefined : clusterType,
      }),
  });

  const clusters = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Clusters</h1>
        <p className="text-sm text-zinc-500">
          Groups of related domains by HTML similarity or shared infrastructure
        </p>
      </div>

      <div className="flex items-center gap-3">
        <select
          value={clusterType}
          onChange={(e) => setClusterType(e.target.value)}
          className="h-9 rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          <option value="all">All Types</option>
          <option value="html_similarity">HTML Similarity</option>
          <option value="infra">Infrastructure</option>
          <option value="phishkit">PhishKit</option>
        </select>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
          ))}
        </div>
      ) : clusters.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Boxes className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">No clusters found.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Type</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Description</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Domains</th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">First Seen</th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {clusters.map((c: Cluster) => (
                <tr key={c.id} className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70">
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${clusterTypeColor(c.cluster_type)}`}>
                      {c.cluster_type.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Link href={`/clusters/${c.id}`} className="font-medium text-zinc-100 hover:text-blue-400 hover:underline">
                      {c.description || c.signature_hash.slice(0, 12) + "..."}
                    </Link>
                  </td>
                  <td className="px-4 py-3 font-mono text-zinc-300">{c.domain_count}</td>
                  <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">
                    {formatDistanceToNow(new Date(c.first_seen), { addSuffix: true })}
                  </td>
                  <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">
                    {formatDistanceToNow(new Date(c.last_seen), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}