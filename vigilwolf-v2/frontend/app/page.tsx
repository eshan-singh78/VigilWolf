"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import {
  Globe,
  AlertTriangle,
  ShieldAlert,
  Bell,
  Plus,
  Webhook,
  Settings,
} from "lucide-react";
import { domainsApi, alertsApi } from "@/lib/api-v2";
import { StatsCard } from "@/components/dashboard/stats-card";
import { ThreatTable, ThreatTableFooter } from "@/components/dashboard/threat-table";
import { AlertsList, AlertsListFooter } from "@/components/dashboard/alerts-list";

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["threatStats"],
    queryFn: () => domainsApi.getThreatStats(),
    refetchInterval: 30_000,
  });

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ["threats", "dashboard"],
    queryFn: () => domainsApi.getThreats({ limit: 10 }),
    refetchInterval: 30_000,
  });

  const { data: alertsData, isLoading: alertsLoading } = useQuery({
    queryKey: ["alerts", "dashboard"],
    queryFn: () => alertsApi.list(),
    refetchInterval: 30_000,
  });

  const { data: monitoredData } = useQuery({
    queryKey: ["monitored"],
    queryFn: () => domainsApi.list({ limit: 1 }),
    refetchInterval: 60_000,
  });

  const threats = threatsData?.items ?? [];
  const alerts = (alertsData?.items ?? []).slice(0, 5);
  const activeThreats = (stats?.high ?? 0) + (stats?.medium ?? 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Dashboard</h1>
        <p className="text-sm text-zinc-500">
          Overview of your monitored attack surface
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatsCard
          title="Domains Monitored"
          value={monitoredData?.total ?? "--"}
          description="across all groups"
          variant="default"
        />
        <StatsCard
          title="Active Threats"
          value={activeThreats}
          description="high + medium risk"
          variant="warning"
        />
        <StatsCard
          title="High Risk Domains"
          value={stats?.high ?? 0}
          description="require immediate attention"
          variant="danger"
        />
        <StatsCard
          title="Alerts Sent Today"
          value={alertsData?.total ?? "--"}
          description="webhook deliveries"
          variant="success"
        />
      </div>

      {/* Quick actions */}
      <div className="flex flex-wrap gap-3">
        <Link
          href="/monitor"
          className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 transition-colors hover:bg-zinc-800 hover:text-zinc-100"
        >
          <Plus className="h-4 w-4" />
          Add Domain
        </Link>
        <Link
          href="/settings/webhooks"
          className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 transition-colors hover:bg-zinc-800 hover:text-zinc-100"
        >
          <Webhook className="h-4 w-4" />
          Configure Webhooks
        </Link>
        <Link
          href="/settings"
          className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 transition-colors hover:bg-zinc-800 hover:text-zinc-100"
        >
          <Settings className="h-4 w-4" />
          View Settings
        </Link>
      </div>

      {/* Main content: threat table + alerts sidebar */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Threat Feed Preview — takes 2/3 on xl */}
        <div className="xl:col-span-2">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-red-400" />
                <h2 className="text-lg font-semibold text-zinc-100">
                  Top Threats
                </h2>
              </div>
              {stats && (
                <div className="flex items-center gap-3 text-xs text-zinc-500">
                  <span className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    {stats.high} high
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-amber-500" />
                    {stats.medium} medium
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-emerald-500" />
                    {stats.low} low
                  </span>
                </div>
              )}
            </div>
            <ThreatTable threats={threats} isLoading={threatsLoading} />
            {threats.length > 0 && <ThreatTableFooter />}
          </div>
        </div>

        {/* Recent Alerts sidebar — takes 1/3 on xl */}
        <div className="xl:col-span-1">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-4 flex items-center gap-2">
              <Bell className="h-5 w-5 text-amber-400" />
              <h2 className="text-lg font-semibold text-zinc-100">
                Recent Alerts
              </h2>
            </div>
            <AlertsList alerts={alerts} isLoading={alertsLoading} />
            {alerts.length > 0 && <AlertsListFooter />}
          </div>
        </div>
      </div>
    </div>
  );
}