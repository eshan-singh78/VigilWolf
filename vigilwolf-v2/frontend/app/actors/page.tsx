"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { Drama } from "lucide-react";
import { actorsApi, type Actor } from "@/lib/api-v2";

function confidenceColor(score: number): string {
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.5) return "text-amber-400";
  return "text-zinc-400";
}

function confidenceLabel(score: number): string {
  if (score >= 0.8) return "LIKELY SAME";
  if (score >= 0.5) return "POSSIBLE";
  return "WEAK";
}

export default function ActorsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["actors"],
    queryFn: () => actorsApi.list(),
  });

  const actors = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Threat Actors</h1>
        <p className="text-sm text-zinc-500">
          Attributed threat actors from campaign and infrastructure correlation
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900" />
          ))}
        </div>
      ) : actors.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Drama className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">No actors profiled yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Label</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Confidence</th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">Campaigns</th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">First Seen</th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {actors.map((a: Actor) => (
                <tr key={a.id} className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70">
                  <td className="px-4 py-3">
                    <Link href={`/actors/${a.id}`} className="font-medium text-zinc-100 hover:text-red-400 hover:underline">
                      {a.label}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-sm font-semibold ${confidenceColor(a.confidence_score)}`}>
                        {(a.confidence_score * 100).toFixed(0)}%
                      </span>
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                        {confidenceLabel(a.confidence_score)}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-zinc-300">{a.campaign_count}</td>
                  <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">
                    {formatDistanceToNow(new Date(a.first_seen), { addSuffix: true })}
                  </td>
                  <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">
                    {formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })}
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