"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowLeft } from "lucide-react";
import { actorsApi } from "@/lib/api-v2";

function confidenceColor(score: number): string {
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.5) return "text-amber-400";
  return "text-zinc-400";
}

function confidenceLabel(score: number): string {
  if (score >= 0.8) return "LIKELY SAME ACTOR";
  if (score >= 0.5) return "POSSIBLE";
  return "WEAK";
}

export default function ActorDetailPage() {
  const params = useParams();
  const router = useRouter();
  const actorId = params.id as string;

  const { data: actor, isLoading } = useQuery({
    queryKey: ["actor", actorId],
    queryFn: () => actorsApi.get(actorId),
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 animate-pulse rounded bg-zinc-800" />
        <div className="h-40 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
      </div>
    );
  }

  if (!actor) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-500">Actor not found.</p>
        <Link href="/actors" className="mt-2 text-sm text-red-400 hover:underline">Back to Actors</Link>
      </div>
    );
  }

  const fp = actor.fingerprint || {};

  return (
    <div className="space-y-6">
      <button onClick={() => router.back()} className="flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300">
        <ArrowLeft className="h-4 w-4" /> Back to Actors
      </button>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h1 className="text-2xl font-bold text-zinc-100">{actor.label}</h1>
        <div className="mt-2 flex items-center gap-3">
          <span className={`font-mono text-lg font-semibold ${confidenceColor(actor.confidence_score)}`}>
            {(actor.confidence_score * 100).toFixed(0)}%
          </span>
          <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            {confidenceLabel(actor.confidence_score)}
          </span>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-4 text-sm text-zinc-400">
          <div>First seen: {formatDistanceToNow(new Date(actor.first_seen), { addSuffix: true })}</div>
          <div>Last seen: {formatDistanceToNow(new Date(actor.last_seen), { addSuffix: true })}</div>
        </div>
      </div>

      {/* Confidence breakdown */}
      {fp && typeof fp === "object" && "shared_signals" in fp && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">Confidence Breakdown</h2>
          <div className="space-y-3">
            {[
              { label: "Shared Kit", value: (fp as Record<string, unknown>).shared_kit ?? 0, weight: 0.3 },
              { label: "Shared Infra", value: (fp as Record<string, unknown>).shared_infra ?? 0, weight: 0.3 },
              { label: "Shared IOCs", value: (fp as Record<string, unknown>).shared_iocs ?? 0, weight: 0.2 },
              { label: "Temporal Overlap", value: (fp as Record<string, unknown>).temporal_overlap ?? 0, weight: 0.2 },
            ].map(({ label, value, weight }) => {
              const score = Number(value) * weight;
              return (
                <div key={label} className="flex items-center gap-3">
                  <span className="w-32 shrink-0 text-sm text-zinc-400">{label}</span>
                  <div className="flex-1">
                    <div className="h-2.5 w-full rounded-full bg-zinc-800">
                      <div className="h-2.5 rounded-full bg-red-500" style={{ width: `${Math.min(score * 100, 100)}%` }} />
                    </div>
                  </div>
                  <span className="w-16 text-right font-mono text-sm text-zinc-400">{(score * 100).toFixed(0)}%</span>
                  <span className="w-12 text-right text-xs text-zinc-600">x{weight}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Linked campaigns */}
      {actor.campaigns && actor.campaigns.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">Linked Campaigns</h2>
          <div className="space-y-2">
            {actor.campaigns.map((c) => (
              <Link key={c.id} href={`/campaigns/${c.id}`} className="block rounded-md border border-zinc-800 p-3 transition-colors hover:bg-zinc-800">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-zinc-100">{c.name}</span>
                  <span className="text-xs text-zinc-500">{c.status}</span>
                </div>
                {c.target_brand && <span className="text-xs text-zinc-500">{c.target_brand} - {c.domain_count} domains</span>}
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}