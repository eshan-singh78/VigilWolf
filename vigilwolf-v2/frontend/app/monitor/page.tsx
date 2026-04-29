"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  Shield,
  FolderOpen,
  Globe,
  Activity,
  Plus,
  X,
  Loader2,
  Users,
} from "lucide-react";
import {
  monitorApi,
  type MonitoringGroup,
  type MonitoredDomain,
} from "@/lib/api-v2";

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <p className="text-sm text-zinc-500">{label}</p>
      </div>
      <p className={`mt-1 text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

export default function MonitorPage() {
  const queryClient = useQueryClient();
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState("");
  const [newDomainGroup, setNewDomainGroup] = useState("");
  const [newDomainFrequency, setNewDomainFrequency] = useState(3600);

  // Fetch groups
  const { data: groups, isLoading: groupsLoading } = useQuery({
    queryKey: ["monitorGroups"],
    queryFn: () => monitorApi.listGroups(),
  });

  // Fetch domains for selected group
  const { data: groupDomains, isLoading: domainsLoading } = useQuery({
    queryKey: ["monitorGroupDomains", selectedGroupId],
    queryFn: () => monitorApi.getGroupDomains(selectedGroupId!),
    enabled: selectedGroupId !== null,
  });

  // Add domain mutation
  const addDomainMutation = useMutation({
    mutationFn: ({
      groupId,
      domain,
      frequency,
    }: {
      groupId: string;
      domain: string;
      frequency: number;
    }) => monitorApi.addDomain(groupId, domain, frequency),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitorGroupDomains", selectedGroupId] });
      queryClient.invalidateQueries({ queryKey: ["monitorGroups"] });
      setNewDomain("");
    },
  });

  // Remove domain mutation
  const removeDomainMutation = useMutation({
    mutationFn: ({
      groupId,
      domainId,
    }: {
      groupId: string;
      domainId: string;
    }) => monitorApi.removeDomain(groupId, domainId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitorGroupDomains", selectedGroupId] });
      queryClient.invalidateQueries({ queryKey: ["monitorGroups"] });
    },
  });

  const typedGroups = (groups as MonitoringGroup[] | undefined) ?? [];
  const typedDomains = (groupDomains as MonitoredDomain[] | undefined) ?? [];

  const totalDomains = typedGroups.reduce(
    (sum, g) => sum + g.domain_count,
    0
  );

  const handleAddDomain = () => {
    if (!newDomain.trim() || !newDomainGroup) return;
    addDomainMutation.mutate({
      groupId: newDomainGroup,
      domain: newDomain.trim(),
      frequency: newDomainFrequency,
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Domain Monitor</h1>
        <p className="text-sm text-zinc-500">
          Manage monitored domains across groups
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {groupsLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-20 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))
        ) : (
          <>
            <StatCard
              label="Total Groups"
              value={typedGroups.length}
              icon={FolderOpen}
              color="text-zinc-100"
            />
            <StatCard
              label="Total Domains"
              value={totalDomains}
              icon={Globe}
              color="text-red-400"
            />
            <StatCard
              label="Active Domains"
              value={totalDomains}
              icon={Activity}
              color="text-green-400"
            />
          </>
        )}
      </div>

      {/* Add domain form */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="mb-3 text-sm font-medium text-zinc-300">
          Add Domain to Monitor
        </h2>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label className="mb-1 block text-xs text-zinc-500">Domain</label>
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
            />
          </div>
          <div className="w-full sm:w-48">
            <label className="mb-1 block text-xs text-zinc-500">Group</label>
            <select
              value={newDomainGroup}
              onChange={(e) => setNewDomainGroup(e.target.value)}
              className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
            >
              <option value="">Select group...</option>
              {typedGroups.map((g: MonitoringGroup) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
          <div className="w-full sm:w-32">
            <label className="mb-1 block text-xs text-zinc-500">
              Frequency (s)
            </label>
            <input
              type="number"
              value={newDomainFrequency}
              onChange={(e) => setNewDomainFrequency(Number(e.target.value))}
              min={60}
              className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
            />
          </div>
          <button
            onClick={handleAddDomain}
            disabled={
              !newDomain.trim() ||
              !newDomainGroup ||
              addDomainMutation.isPending
            }
            className="flex h-9 items-center justify-center gap-1.5 rounded-md bg-red-600 px-4 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {addDomainMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Plus className="h-4 w-4" />
            )}
            Add
          </button>
        </div>
      </div>

      {/* Group cards */}
      {groupsLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-28 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))}
        </div>
      ) : typedGroups.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Users className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">
            No monitoring groups yet. Create a group to start monitoring
            domains.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {typedGroups.map((group: MonitoringGroup) => (
            <button
              key={group.id}
              onClick={() =>
                setSelectedGroupId(
                  selectedGroupId === group.id ? null : group.id
                )
              }
              className={`rounded-lg border p-4 text-left transition-colors ${
                selectedGroupId === group.id
                  ? "border-red-500/50 bg-zinc-900"
                  : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <h3 className="truncate font-medium text-zinc-100">
                    {group.name}
                  </h3>
                  {group.description && (
                    <p className="mt-1 line-clamp-2 text-xs text-zinc-500">
                      {group.description}
                    </p>
                  )}
                </div>
                <div className="ml-3 flex shrink-0 items-center gap-1 rounded bg-zinc-800 px-2 py-0.5">
                  <Globe className="h-3 w-3 text-zinc-500" />
                  <span className="text-xs font-medium text-zinc-300">
                    {group.domain_count}
                  </span>
                </div>
              </div>
              <p className="mt-2 text-xs text-zinc-600">
                Created{" "}
                {group.created_at
                  ? formatDistanceToNow(new Date(group.created_at), {
                      addSuffix: true,
                    })
                  : "unknown"}
              </p>
            </button>
          ))}
        </div>
      )}

      {/* Domain list for selected group */}
      {selectedGroupId && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-zinc-300">
              Domains in{" "}
              {typedGroups.find((g) => g.id === selectedGroupId)?.name ??
                "Group"}
            </h2>
            <button
              onClick={() => setSelectedGroupId(null)}
              className="text-xs text-zinc-500 transition-colors hover:text-zinc-300"
            >
              Close
            </button>
          </div>

          {domainsLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="h-10 animate-pulse rounded bg-zinc-800"
                />
              ))}
            </div>
          ) : typedDomains.length === 0 ? (
            <p className="py-4 text-center text-sm text-zinc-500">
              No domains in this group yet.
            </p>
          ) : (
            <div className="space-y-2">
              {typedDomains.map((domain: MonitoredDomain) => (
                <div
                  key={domain.id}
                  className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 px-4 py-2.5"
                >
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-zinc-600" />
                    <span className="text-sm font-medium text-zinc-200">
                      {domain.domain}
                    </span>
                    {domain.risk_score !== null && (
                      <span
                        className={`font-mono text-xs ${
                          domain.risk_score >= 70
                            ? "text-red-400"
                            : domain.risk_score >= 40
                              ? "text-amber-400"
                              : "text-green-400"
                        }`}
                      >
                        {domain.risk_score}
                      </span>
                    )}
                    <span className="text-xs text-zinc-600">
                      Added{" "}
                      {formatDistanceToNow(new Date(domain.added_at), {
                        addSuffix: true,
                      })}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      removeDomainMutation.mutate({
                        groupId: selectedGroupId,
                        domainId: domain.id,
                      })
                    }
                    disabled={removeDomainMutation.isPending}
                    className="rounded p-1 text-zinc-600 transition-colors hover:bg-zinc-800 hover:text-red-400"
                    title="Remove domain"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}