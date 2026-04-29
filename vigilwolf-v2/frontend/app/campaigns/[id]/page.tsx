"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowLeft } from "lucide-react";
import { campaignsApi } from "@/lib/api-v2";

function statusColor(status: string): string {
  switch (status) {
    case "active": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "dormant": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "closed": return "bg-green-500/20 text-green-400 border-green-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function CampaignDetailPage() {
  const params = useParams();
  const router = useRouter();
  const campaignId = params.id as string;

  const { data: campaign, isLoading } = useQuery({
    queryKey: ["campaign", campaignId],
    queryFn: () => campaignsApi.get(campaignId),
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 animate-pulse rounded bg-zinc-800" />
        <div className="h-40 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-500">Campaign not found.</p>
        <Link href="/campaigns" className="mt-2 text-sm text-red-400 hover:underline">Back to Campaigns</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <button onClick={() => router.back()} className="flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300">
        <ArrowLeft className="h-4 w-4" /> Back to Campaigns
      </button>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h1 className="text-2xl font-bold text-zinc-100">{campaign.name}</h1>
        <div className="mt-2 flex items-center gap-3">
          <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-medium ${statusColor(campaign.status)}`}>
            {campaign.status}
          </span>
          {campaign.target_brand && (
            <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
              {campaign.target_brand}
            </span>
          )}
        </div>
        <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
          <div><span className="text-zinc-500">Domains:</span> <span className="font-mono text-zinc-100">{campaign.domain_count}</span></div>
          <div><span className="text-zinc-500">First seen:</span> <span className="text-zinc-300">{formatDistanceToNow(new Date(campaign.first_seen), { addSuffix: true })}</span></div>
          <div><span className="text-zinc-500">Last seen:</span> <span className="text-zinc-300">{formatDistanceToNow(new Date(campaign.last_seen), { addSuffix: true })}</span></div>
        </div>
      </div>

      {campaign.clusters && campaign.clusters.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">Linked Clusters</h2>
          <div className="space-y-2">
            {campaign.clusters.map((c) => (
              <Link key={c.id} href={`/clusters/${c.id}`} className="block rounded-md border border-zinc-800 p-3 transition-colors hover:bg-zinc-800">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-zinc-100">{c.description || c.signature_hash.slice(0, 16)}</span>
                  <span className="text-xs text-zinc-500">{c.cluster_type.replace("_", " ")}</span>
                </div>
                <span className="text-xs text-zinc-500">{c.domain_count} domains</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}