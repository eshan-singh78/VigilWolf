"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowLeft, Boxes } from "lucide-react";
import { clustersApi } from "@/lib/api-v2";

function clusterTypeColor(type: string): string {
  switch (type) {
    case "html_similarity": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "infra": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "phishkit": return "bg-red-500/20 text-red-400 border-red-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function ClusterDetailPage() {
  const params = useParams();
  const router = useRouter();
  const clusterId = params.id as string;

  const { data: cluster, isLoading } = useQuery({
    queryKey: ["cluster", clusterId],
    queryFn: () => clustersApi.get(clusterId),
  });

  const { data: domainsData } = useQuery({
    queryKey: ["clusterDomains", clusterId],
    queryFn: () => clustersApi.getDomains(clusterId),
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 animate-pulse rounded bg-zinc-800" />
        <div className="h-40 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
      </div>
    );
  }

  if (!cluster) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-500">Cluster not found.</p>
        <Link href="/clusters" className="mt-2 text-sm text-blue-400 hover:underline">Back to Clusters</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <button onClick={() => router.back()} className="flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300">
        <ArrowLeft className="h-4 w-4" /> Back to Clusters
      </button>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">{cluster.description || "Cluster"}</h1>
            <div className="mt-2 flex items-center gap-3">
              <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-medium ${clusterTypeColor(cluster.cluster_type)}`}>
                {cluster.cluster_type.replace("_", " ")}
              </span>
              <span className="font-mono text-sm text-zinc-500">{cluster.signature_hash.slice(0, 16)}...</span>
            </div>
          </div>
          <div className="text-right">
            <p className="text-sm text-zinc-500">Domains</p>
            <p className="text-2xl font-bold text-zinc-100">{cluster.domain_count}</p>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-4 text-sm text-zinc-400">
          <div>First seen: {formatDistanceToNow(new Date(cluster.first_seen), { addSuffix: true })}</div>
          <div>Last seen: {formatDistanceToNow(new Date(cluster.last_seen), { addSuffix: true })}</div>
          <div>Signature type: {cluster.signature_type}</div>
        </div>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h2 className="mb-4 text-lg font-semibold text-zinc-100">Member Domains</h2>
        {domainsData?.items && domainsData.items.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-4 py-2 text-left font-medium text-zinc-400">Domain</th>
                  <th className="px-4 py-2 text-left font-medium text-zinc-400">Confidence</th>
                  <th className="px-4 py-2 text-left font-medium text-zinc-400">Joined</th>
                </tr>
              </thead>
              <tbody>
                {domainsData.items.map((d) => (
                  <tr key={d.id} className="border-b border-zinc-800/50 hover:bg-zinc-900/70">
                    <td className="px-4 py-2">
                      <Link href={`/threats/${d.id}`} className="font-medium text-zinc-100 hover:text-red-400 hover:underline">
                        {d.domain || d.id}
                      </Link>
                    </td>
                    <td className="px-4 py-2 font-mono text-zinc-300">{(d.confidence * 100).toFixed(0)}%</td>
                    <td className="px-4 py-2 text-zinc-500">--</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No domains in this cluster.</p>
        )}
      </div>
    </div>
  );
}