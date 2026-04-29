import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowRight, ShieldAlert } from "lucide-react";
import type { ThreatDomain } from "@/lib/api-v2";

function severityColor(severity: string): string {
  switch (severity) {
    case "high":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "medium":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "low":
      return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

function riskScoreColor(score: number): string {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
}

interface ThreatTableProps {
  threats: ThreatDomain[];
  isLoading?: boolean;
}

export function ThreatTable({ threats, isLoading }: ThreatTableProps) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-14 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
          />
        ))}
      </div>
    );
  }

  if (threats.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
        <ShieldAlert className="h-8 w-8 text-zinc-600" />
        <p className="mt-2 text-sm text-zinc-500">
          No threats detected yet. Add domains to start monitoring.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-800 bg-zinc-900/50">
            <th className="px-4 py-3 text-left font-medium text-zinc-400">
              Domain
            </th>
            <th className="px-4 py-3 text-left font-medium text-zinc-400">
              Risk Score
            </th>
            <th className="px-4 py-3 text-left font-medium text-zinc-400">
              Severity
            </th>
            <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 md:table-cell">
              Signals
            </th>
            <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 sm:table-cell">
              Last Checked
            </th>
          </tr>
        </thead>
        <tbody>
          {threats.map((threat) => (
            <tr
              key={threat.id}
              className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
            >
              <td className="px-4 py-3">
                <Link
                  href={`/threats/${threat.id}`}
                  className="font-medium text-zinc-100 hover:text-red-400 hover:underline"
                >
                  {threat.domain}
                </Link>
              </td>
              <td className="px-4 py-3">
                <span
                  className={`font-mono font-semibold ${riskScoreColor(threat.risk_score)}`}
                >
                  {threat.risk_score}
                </span>
              </td>
              <td className="px-4 py-3">
                <span
                  className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${severityColor(threat.severity)}`}
                >
                  {threat.severity.charAt(0).toUpperCase() +
                    threat.severity.slice(1)}
                </span>
              </td>
              <td className="hidden px-4 py-3 md:table-cell">
                <div className="flex flex-wrap gap-1">
                  {threat.dominant_signals
                    ?.slice(0, 3)
                    .map((signal: string) => (
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
              </td>
              <td className="hidden px-4 py-3 text-zinc-500 sm:table-cell">
                {threat.last_checked
                  ? formatDistanceToNow(new Date(threat.last_checked), {
                      addSuffix: true,
                    })
                  : "--"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ThreatTableFooter() {
  return (
    <div className="flex justify-center pt-4">
      <Link
        href="/threats"
        className="inline-flex items-center gap-1.5 text-sm font-medium text-red-400 transition-colors hover:text-red-300"
      >
        View All Threats
        <ArrowRight className="h-4 w-4" />
      </Link>
    </div>
  );
}