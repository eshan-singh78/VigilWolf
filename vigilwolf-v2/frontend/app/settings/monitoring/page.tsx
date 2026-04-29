"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useCallback } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Plus,
  Pencil,
  Trash2,
  Globe,
  X,
  Check,
  Loader2,
} from "lucide-react";
import { monitorApi, type MonitoringGroup } from "@/lib/api-v2";

function GroupForm({
  initial,
  onSubmit,
  onCancel,
  submitting,
}: {
  initial?: MonitoringGroup;
  onSubmit: (data: { name: string; description: string }) => void;
  onCancel: () => void;
  submitting: boolean;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ name, description });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          Group Name
        </label>
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          placeholder="e.g., Brand Protection"
        />
      </div>
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          Description
        </label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
          className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          placeholder="Optional description of this monitoring group"
        />
      </div>
      <div className="flex items-center gap-3 pt-2">
        <button
          type="submit"
          disabled={submitting}
          className="flex items-center gap-1.5 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
        >
          {submitting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Check className="h-4 w-4" />
          )}
          {initial ? "Update" : "Create"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
        >
          <X className="h-4 w-4" />
          Cancel
        </button>
      </div>
    </form>
  );
}

export default function MonitoringGroupsPage() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingGroup, setEditingGroup] = useState<MonitoringGroup | null>(
    null,
  );
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const { data: groups, isLoading } = useQuery({
    queryKey: ["monitoringGroups"],
    queryFn: () => monitorApi.listGroups(),
  });

  const createMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) =>
      monitorApi.createGroup(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitoringGroups"] });
      setShowForm(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: string;
      data: Partial<{ name: string; description: string }>;
    }) => monitorApi.updateGroup(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitoringGroups"] });
      setEditingGroup(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => monitorApi.removeGroup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitoringGroups"] });
      setDeleteConfirm(null);
    },
  });

  const handleCreate = useCallback(
    (data: { name: string; description: string }) =>
      createMutation.mutate(data),
    [createMutation],
  );

  const handleUpdate = useCallback(
    (data: { name: string; description: string }) => {
      if (editingGroup) {
        updateMutation.mutate({ id: editingGroup.id, data });
      }
    },
    [editingGroup, updateMutation],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          href="/settings"
          className="flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300"
        >
          <ArrowLeft className="h-4 w-4" />
          Settings
        </Link>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">
            Monitoring Groups
          </h1>
          <p className="text-sm text-zinc-500">
            Organize monitored domains into groups
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-1.5 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700"
        >
          <Plus className="h-4 w-4" />
          New Group
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">
            New Monitoring Group
          </h2>
          <GroupForm
            onSubmit={handleCreate}
            onCancel={() => setShowForm(false)}
            submitting={createMutation.isPending}
          />
        </div>
      )}

      {/* Edit form */}
      {editingGroup && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">
            Edit Group
          </h2>
          <GroupForm
            initial={editingGroup}
            onSubmit={handleUpdate}
            onCancel={() => setEditingGroup(null)}
            submitting={updateMutation.isPending}
          />
        </div>
      )}

      {/* Delete confirmation */}
      {deleteConfirm && (
        <div className="rounded-lg border border-red-900/50 bg-red-950/30 p-6">
          <p className="text-sm text-zinc-300">
            Are you sure you want to delete this monitoring group? Domains in
            the group will not be removed from monitoring.
          </p>
          <div className="mt-4 flex items-center gap-3">
            <button
              onClick={() => deleteMutation.mutate(deleteConfirm)}
              disabled={deleteMutation.isPending}
              className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </button>
            <button
              onClick={() => setDeleteConfirm(null)}
              className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Groups list */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-20 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))}
        </div>
      ) : !groups || groups.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <Globe className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-2 text-sm text-zinc-500">
            No monitoring groups created yet.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {groups.map((group: MonitoringGroup) => (
            <div
              key={group.id}
              className="rounded-lg border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-zinc-100">
                    {group.name}
                  </h3>
                  {group.description && (
                    <p className="mt-1 text-xs text-zinc-500">
                      {group.description}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setEditingGroup(group)}
                    className="rounded p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                    title="Edit group"
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => setDeleteConfirm(group.id)}
                    className="rounded p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-red-400"
                    title="Delete group"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-2">
                <Globe className="h-3.5 w-3.5 text-zinc-600" />
                <span className="text-sm text-zinc-400">
                  {group.domain_count}{" "}
                  {group.domain_count === 1 ? "domain" : "domains"}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}