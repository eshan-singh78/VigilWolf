"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import {
  Settings,
  SlidersHorizontal,
  Plug,
  Bell,
  Webhook,
  Activity,
  Loader2,
} from "lucide-react";
import {
  pluginsApi,
  settingsApi,
  type Plugin,
  type RiskThresholds,
} from "@/lib/api-v2";

function SectionCard({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
      <div className="mb-4 flex items-center gap-2">
        <Icon className="h-5 w-5 text-red-400" />
        <h2 className="text-lg font-semibold text-zinc-100">{title}</h2>
      </div>
      {children}
    </div>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();

  const { data: plugins, isLoading: pluginsLoading } = useQuery({
    queryKey: ["plugins"],
    queryFn: () => pluginsApi.list(),
  });

  const { data: thresholds, isLoading: thresholdsLoading } = useQuery({
    queryKey: ["riskThresholds"],
    queryFn: () => settingsApi.getRiskThresholds(),
  });

  const { data: dryRun } = useQuery({
    queryKey: ["dryRunStatus"],
    queryFn: () => settingsApi.getDryRunStatus(),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      pluginsApi.toggle(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["plugins"] });
    },
  });

  const weightMutation = useMutation({
    mutationFn: ({ id, weight }: { id: string; weight: number }) =>
      pluginsApi.updateWeight(id, weight),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["plugins"] });
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Settings</h1>
        <p className="text-sm text-zinc-500">
          Configure risk thresholds, plugins, and alert delivery
        </p>
      </div>

      {/* Risk Thresholds */}
      <SectionCard title="Risk Thresholds" icon={SlidersHorizontal}>
        {thresholdsLoading ? (
          <div className="h-16 animate-pulse rounded bg-zinc-800" />
        ) : (
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-md border border-zinc-800 bg-zinc-950 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500">
                High Threshold
              </p>
              <p className="mt-1 text-2xl font-bold text-red-400">
                {thresholds ? (thresholds as RiskThresholds).high : 70}
              </p>
              <p className="mt-1 text-xs text-zinc-600">
                Scores above this are classified as high risk
              </p>
            </div>
            <div className="rounded-md border border-zinc-800 bg-zinc-950 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500">
                Medium Threshold
              </p>
              <p className="mt-1 text-2xl font-bold text-amber-400">
                {thresholds ? (thresholds as RiskThresholds).medium : 40}
              </p>
              <p className="mt-1 text-xs text-zinc-600">
                Scores above this are classified as medium risk
              </p>
            </div>
          </div>
        )}
        <p className="mt-3 text-xs text-zinc-600">
          Thresholds are read-only in Phase 1. Contact your administrator to
          modify.
        </p>
      </SectionCard>

      {/* Plugin Weights */}
      <SectionCard title="Plugin Weights" icon={Settings}>
        {pluginsLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="h-10 animate-pulse rounded bg-zinc-800"
              />
            ))}
          </div>
        ) : plugins && plugins.length > 0 ? (
          <div className="space-y-3">
            {plugins.map((plugin: Plugin) => (
              <div
                key={plugin.id}
                className="flex items-center gap-4 rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3"
              >
                <span className="w-36 shrink-0 truncate text-sm font-medium text-zinc-300">
                  {plugin.name}
                </span>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={plugin.weight}
                  onChange={(e) => {
                    const newWeight = Number(e.target.value);
                    weightMutation.mutate({
                      id: plugin.id,
                      weight: newWeight,
                    });
                  }}
                  className="h-2 flex-1 cursor-pointer appearance-none rounded-full bg-zinc-800 accent-red-500"
                />
                <span className="w-10 text-right font-mono text-sm text-zinc-400">
                  {plugin.weight}
                </span>
                {weightMutation.isPending && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-zinc-500" />
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No plugins registered.</p>
        )}
      </SectionCard>

      {/* Plugin Enable/Disable */}
      <SectionCard title="Plugin Enable/Disable" icon={Plug}>
        {pluginsLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="h-10 animate-pulse rounded bg-zinc-800"
              />
            ))}
          </div>
        ) : plugins && plugins.length > 0 ? (
          <div className="space-y-2">
            {plugins.map((plugin: Plugin) => (
              <div
                key={plugin.id}
                className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-zinc-300">
                    {plugin.name}
                  </span>
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">
                    {plugin.category}
                  </span>
                </div>
                <button
                  onClick={() =>
                    toggleMutation.mutate({
                      id: plugin.id,
                      enabled: !plugin.enabled,
                    })
                  }
                  disabled={toggleMutation.isPending}
                  className={`relative h-6 w-11 rounded-full transition-colors ${
                    plugin.enabled ? "bg-red-600" : "bg-zinc-700"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                      plugin.enabled ? "translate-x-5.5" : "translate-x-0.5"
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No plugins registered.</p>
        )}
      </SectionCard>

      {/* Alert Configuration */}
      <SectionCard title="Alert Configuration" icon={Bell}>
        <div className="space-y-4">
          <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3">
            <div>
              <p className="text-sm font-medium text-zinc-300">
                Webhook Endpoints
              </p>
              <p className="text-xs text-zinc-600">
                Manage alert delivery webhooks
              </p>
            </div>
            <Link
              href="/settings/webhooks"
              className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
            >
              <Webhook className="h-4 w-4" />
              Manage Webhooks
            </Link>
          </div>
          <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3">
            <div>
              <p className="text-sm font-medium text-zinc-300">
                Dry-Run Mode
              </p>
              <p className="text-xs text-zinc-600">
                When enabled, alerts are logged but not delivered
              </p>
            </div>
            <span
              className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${
                dryRun?.enabled
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                  : "bg-green-500/20 text-green-400 border-green-500/30"
              }`}
            >
              {dryRun?.enabled ? "Active" : "Inactive"}
            </span>
          </div>
          <Link
            href="/settings/monitoring"
            className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3 transition-colors hover:border-zinc-700"
          >
            <div>
              <p className="text-sm font-medium text-zinc-300">
                Monitoring Groups
              </p>
              <p className="text-xs text-zinc-600">
                Manage domain monitoring groups
              </p>
            </div>
            <Activity className="h-4 w-4 text-zinc-500" />
          </Link>
        </div>
      </SectionCard>
    </div>
  );
}