"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { Bell, RefreshCw, Filter } from "lucide-react";
import { alertsApi, type Alert } from "@/lib/api-v2";

function severityBadge(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-500/20 text-red-400 border-red-500/30";
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

function statusBadge(status?: string): string {
  switch (status) {
    case "sent":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    case "failed":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "retrying":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function AlertsPage() {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: alertsData, isLoading } = useQuery({
    queryKey: ["alerts", severityFilter],
    queryFn: () =>
      alertsApi.list({
        severity: severityFilter === "all" ? undefined : severityFilter,
      }),
    refetchInterval: 30_000,
  });

  const retryMutation = useMutation({
    mutationFn: (id: string) => alertsApi.retry(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const alerts = alertsData?.items ?? [];

  // Client-side status filter since API may not support it
  const filteredAlerts =
    statusFilter === "all"
      ? alerts
      : alerts.filter((a: Alert) => a.status === statusFilter);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Alerts</h1>
        <p className="text-sm text-zinc-500">
          Webhook delivery alerts and notifications
        </p>
      </div>

      {/* Filter bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-zinc-500" />
          <span className="text-sm text-zinc-400">Filters:</span>
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="h-9 rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="h-9 rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          <option value="all">All Statuses</option>
          <option value="sent">Sent</option>
          <option value="failed">Failed</option>
          <option value="retrying">Retrying</option>
        </select>
      </div>

      {/* Alerts table */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              className="h-14 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))}
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Bell className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">
            No alerts found matching your filters.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Domain
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Event
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Severity
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Status
                </th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 md:table-cell">
                  Webhook
                </th>
                <th className="px-4 py-3 text-right font-medium text-zinc-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert: Alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
                >
                  <td className="whitespace-nowrap px-4 py-3 text-zinc-500">
                    {formatDistanceToNow(new Date(alert.created_at), {
                      addSuffix: true,
                    })}
                  </td>
                  <td className="px-4 py-3 font-medium text-zinc-200">
                    {alert.domain}
                  </td>
                  <td className="px-4 py-3 text-zinc-400">
                    {alert.title || alert.message}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${severityBadge(alert.severity)}`}
                    >
                      {alert.severity.charAt(0).toUpperCase() +
                        alert.severity.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${statusBadge(alert.status)}`}
                    >
                      {alert.status
                        ? alert.status.charAt(0).toUpperCase() +
                          alert.status.slice(1)
                        : "Sent"}
                    </span>
                  </td>
                  <td className="hidden px-4 py-3 text-zinc-500 md:table-cell">
                    {alert.webhook_name || "--"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {alert.status === "failed" && (
                      <button
                        onClick={() => retryMutation.mutate(String(alert.id))}
                        disabled={retryMutation.isPending}
                        className="flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300 transition-colors hover:bg-zinc-800 hover:text-zinc-100 disabled:opacity-50"
                      >
                        <RefreshCw className="h-3 w-3" />
                        Retry
                      </button>
                    )}
                    {!alert.acknowledged && alert.status !== "failed" && (
                      <span className="text-xs text-zinc-600">Active</span>
                    )}
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