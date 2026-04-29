"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { Swords } from "lucide-react";
import { campaignsApi, type Campaign } from "@/lib/api-v2";

function statusColor(status: string): string {
  switch (status) {
    case "active":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "dormant":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "closed":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function CampaignsPage() {
  const [status, setStatus] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["campaigns", status],
    queryFn: () =>
      campaignsApi.list({
        status: status === "all" ? undefined : status,
      }),
  });

  const campaigns = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Campaigns</h1>
        <p className="text-sm text-zinc-500">
          Coordinated phishing campaigns detected from cluster correlation
        </p>
      </div>

      <div className="flex items-center gap-3">
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="h-9 rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="dormant">Dormant</option>
          <option value="closed">Closed</option>
        </select>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
          ))}
        </div>
      ) : campaigns.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Swords className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">No campaigns detected yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Name</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Brand</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Status</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Domains</th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c: Campaign) => (
                <tr key={c.id} className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70">
                  <td className="px-4 py-3">
                    <Link href={`/campaigns/${c.id}`} className="font-medium text-zinc-100 hover:text-red-400 hover:underline">
                      {c.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-zinc-300">{c.target_brand || "--"}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(c.status)}`}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-zinc-300">{c.domain_count}</td>
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