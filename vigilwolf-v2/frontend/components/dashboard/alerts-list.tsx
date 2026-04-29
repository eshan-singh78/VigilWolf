import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { ArrowRight, Bell } from "lucide-react";
import type { Alert } from "@/lib/api-v2";

function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
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

interface AlertsListProps {
  alerts: Alert[];
  isLoading?: boolean;
}

export function AlertsList({ alerts, isLoading }: AlertsListProps) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-12 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
          />
        ))}
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 p-6 text-center">
        <Bell className="h-6 w-6 text-zinc-600" />
        <p className="mt-2 text-sm text-zinc-500">No recent alerts</p>
      </div>
    );
  }

  return (
    <ul className="space-y-1">
      {alerts.map((alert) => (
        <li key={alert.id}>
          <Link
            href="/alerts"
            className="flex items-center gap-3 rounded-md px-3 py-2.5 transition-colors hover:bg-zinc-800/50"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-sm font-medium text-zinc-200">
                  {alert.title || alert.message}
                </span>
                <span
                  className={`shrink-0 inline-flex rounded-full border px-1.5 py-px text-[10px] font-medium ${severityColor(alert.severity)}`}
                >
                  {alert.severity.charAt(0).toUpperCase() +
                    alert.severity.slice(1)}
                </span>
              </div>
              <div className="mt-0.5 flex items-center gap-2 text-xs text-zinc-500">
                <span className="truncate">{alert.domain}</span>
                <span className="shrink-0">
                  {formatDistanceToNow(new Date(alert.created_at), {
                    addSuffix: true,
                  })}
                </span>
              </div>
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export function AlertsListFooter() {
  return (
    <div className="flex justify-center pt-3">
      <Link
        href="/alerts"
        className="inline-flex items-center gap-1.5 text-sm font-medium text-red-400 transition-colors hover:text-red-300"
      >
        View All Alerts
        <ArrowRight className="h-4 w-4" />
      </Link>
    </div>
  );
}