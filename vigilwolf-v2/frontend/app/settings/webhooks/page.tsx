"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useCallback } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import {
  Plus,
  Pencil,
  Trash2,
  Send,
  ArrowLeft,
  X,
  Check,
  Loader2,
} from "lucide-react";
import {
  webhooksApi,
  type Webhook,
  type CreateWebhook,
} from "@/lib/api-v2";

const AVAILABLE_EVENTS = [
  "phishing_detected",
  "risk_score_changed",
  "domain_registered",
  "scan_completed",
  "monitoring_alert",
] as const;

function WebhookForm({
  initial,
  onSubmit,
  onCancel,
  submitting,
}: {
  initial?: Webhook;
  onSubmit: (data: CreateWebhook) => void;
  onCancel: () => void;
  submitting: boolean;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<string[]>(initial?.events ?? []);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);

  const toggleEvent = (event: string) => {
    setEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event],
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ name, url, events, enabled });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          Name
        </label>
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          placeholder="My Webhook"
        />
      </div>
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          URL
        </label>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          placeholder="https://hooks.example.com/vigilwolf"
        />
      </div>
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          Secret (optional)
        </label>
        <input
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
          placeholder="HMAC signature secret"
        />
      </div>
      <div>
        <label className="mb-1 block text-sm font-medium text-zinc-400">
          Events
        </label>
        <div className="flex flex-wrap gap-2">
          {AVAILABLE_EVENTS.map((event) => (
            <button
              key={event}
              type="button"
              onClick={() => toggleEvent(event)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                events.includes(event)
                  ? "border-red-500/50 bg-red-500/20 text-red-400"
                  : "border-zinc-700 bg-zinc-900 text-zinc-500 hover:border-zinc-600 hover:text-zinc-400"
              }`}
            >
              {event}
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-zinc-400">Enabled</label>
        <button
          type="button"
          onClick={() => setEnabled(!enabled)}
          className={`relative h-6 w-11 rounded-full transition-colors ${
            enabled ? "bg-red-600" : "bg-zinc-700"
          }`}
        >
          <span
            className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
              enabled ? "translate-x-5.5" : "translate-x-0.5"
            }`}
          />
        </button>
      </div>
      <div className="flex items-center gap-3 pt-2">
        <button
          type="submit"
          disabled={submitting || events.length === 0}
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

export default function WebhooksPage() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    id: string;
    ok: boolean;
  } | null>(null);

  const { data: webhooks, isLoading } = useQuery({
    queryKey: ["webhooks"],
    queryFn: () => webhooksApi.list(),
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateWebhook) => webhooksApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setShowForm(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateWebhook> }) =>
      webhooksApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setEditingWebhook(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setDeleteConfirm(null);
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.test(id),
    onSuccess: (result, id) => {
      setTestResult({ id, ok: result.ok });
      setTimeout(() => setTestResult(null), 5000);
    },
  });

  const handleCreate = useCallback(
    (data: CreateWebhook) => createMutation.mutate(data),
    [createMutation],
  );

  const handleUpdate = useCallback(
    (data: CreateWebhook) => {
      if (editingWebhook) {
        updateMutation.mutate({ id: editingWebhook.id, data });
      }
    },
    [editingWebhook, updateMutation],
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
            Webhook Management
          </h1>
          <p className="text-sm text-zinc-500">
            Configure webhook endpoints for alert delivery
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-1.5 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700"
        >
          <Plus className="h-4 w-4" />
          Add Webhook
        </button>
      </div>

      {/* Add webhook form */}
      {showForm && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">
            New Webhook
          </h2>
          <WebhookForm
            onSubmit={handleCreate}
            onCancel={() => setShowForm(false)}
            submitting={createMutation.isPending}
          />
        </div>
      )}

      {/* Edit webhook form */}
      {editingWebhook && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-4 text-lg font-semibold text-zinc-100">
            Edit Webhook
          </h2>
          <WebhookForm
            initial={editingWebhook}
            onSubmit={handleUpdate}
            onCancel={() => setEditingWebhook(null)}
            submitting={updateMutation.isPending}
          />
        </div>
      )}

      {/* Delete confirmation */}
      {deleteConfirm && (
        <div className="rounded-lg border border-red-900/50 bg-red-950/30 p-6">
          <p className="text-sm text-zinc-300">
            Are you sure you want to delete this webhook? This action cannot be
            undone.
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

      {/* Webhooks table */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-16 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
            />
          ))}
        </div>
      ) : !webhooks || webhooks.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center">
          <p className="text-sm text-zinc-500">
            No webhooks configured yet.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Name
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  URL
                </th>
                <th className="hidden px-4 py-3 text-left font-medium text-zinc-400 lg:table-cell">
                  Events
                </th>
                <th className="px-4 py-3 text-left font-medium text-zinc-400">
                  Enabled
                </th>
                <th className="px-4 py-3 text-right font-medium text-zinc-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh: Webhook) => (
                <tr
                  key={wh.id}
                  className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70"
                >
                  <td className="px-4 py-3 font-medium text-zinc-200">
                    {wh.name}
                  </td>
                  <td className="max-w-[200px] truncate px-4 py-3 text-zinc-500">
                    {wh.url}
                  </td>
                  <td className="hidden px-4 py-3 lg:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {wh.events.slice(0, 2).map((event) => (
                        <span
                          key={event}
                          className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400"
                        >
                          {event}
                        </span>
                      ))}
                      {wh.events.length > 2 && (
                        <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">
                          +{wh.events.length - 2}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${
                        wh.enabled
                          ? "bg-green-500/20 text-green-400 border-green-500/30"
                          : "bg-zinc-500/20 text-zinc-500 border-zinc-500/30"
                      }`}
                    >
                      {wh.enabled ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => testMutation.mutate(wh.id)}
                        disabled={testMutation.isPending}
                        className="rounded p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300 disabled:opacity-50"
                        title="Test webhook"
                      >
                        <Send className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setEditingWebhook(wh)}
                        className="rounded p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                        title="Edit webhook"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteConfirm(wh.id)}
                        className="rounded p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-red-400"
                        title="Delete webhook"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                    {testResult?.id === wh.id && (
                      <p
                        className={`mt-1 text-xs ${testResult.ok ? "text-green-400" : "text-red-400"}`}
                      >
                        {testResult.ok ? "Test passed" : "Test failed"}
                      </p>
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