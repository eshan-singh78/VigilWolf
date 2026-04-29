'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useTheme } from 'next-themes'
import {
  AlertTriangle,
  Trash2,
  RefreshCw,
  Settings2,
  Monitor,
  Shield,
  Clock,
  Image as ImageIcon,
  Database,
  Sun,
  Moon,
  Server
} from 'lucide-react'
import { getApiUrl, API_ENDPOINTS, getAuthHeaders } from '@/lib/api'
import { toast } from '@/hooks/use-toast'
import Navbar from '@/components/navbar'

interface SystemConfig {
  environment: string
  monitoring: {
    screenshot_enabled: boolean
    screenshot_width: number
    screenshot_height: number
    max_concurrent_checks: number
    default_timeout_seconds: number
    max_domains_per_group: number
    snapshot_retention_days: number
    min_check_frequency_seconds: number
    alert_threshold: number
  }
  security: {
    api_key_configured: boolean
    rate_limit_per_minute: number
    force_https: boolean
    trusted_hosts: string[]
  }
  scheduler: {
    timezone: string
    max_instances: number
    coalesce: boolean
  }
  features: {
    prometheus_enabled: boolean
    redis_available: boolean
  }
}

export default function SettingsPage() {
  const router = useRouter()
  const { theme, setTheme, resolvedTheme } = useTheme()
  const [mounted, setMounted] = useState(false)
  const [config, setConfig] = useState<SystemConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [isResetting, setIsResetting] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [resetStats, setResetStats] = useState<{
    groups_deleted: number
    domains_deleted: number
    snapshots_deleted: number
  } | null>(null)

  useEffect(() => {
    setMounted(true)
    fetchConfig()
  }, [])

  const fetchConfig = async () => {
    try {
      const response = await fetch(getApiUrl(API_ENDPOINTS.CONFIG), {
        headers: getAuthHeaders()
      })
      if (!response.ok) throw new Error('Failed to fetch config')
      const data = await response.json()
      setConfig(data)
    } catch (error) {
      console.error('Error fetching config:', error)
      toast({
        title: 'Error',
        description: 'Failed to load system configuration.',
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }

  const handleResetEnvironment = async () => {
    try {
      setIsResetting(true)
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_RESET), {
        method: 'POST',
        headers: getAuthHeaders()
      })

      if (!response.ok) {
        throw new Error('Failed to reset environment')
      }

      const data = await response.json()
      setResetStats(data.statistics)
      setShowConfirmDialog(false)

      toast({
        title: 'Success',
        description: 'Environment reset successfully.',
      })

      setTimeout(() => {
        router.push('/')
      }, 3000)
    } catch (error) {
      console.error('Error resetting environment:', error)
      toast({
        title: 'Error',
        description: 'Failed to reset environment. Please try again.',
        variant: 'destructive',
      })
    } finally {
      setIsResetting(false)
    }
  }

  if (!mounted) return null

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="p-6 pt-24">
        <div className="max-w-5xl mx-auto space-y-6">
          {/* Header */}
          <div>
            <h1 className="text-2xl font-bold text-foreground">Settings</h1>
            <p className="text-muted-foreground mt-1">
              Manage your monitoring system configuration
            </p>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading configuration...</span>
            </div>
          ) : (
            <>
              {/* System Configuration */}
              <div className="bg-card rounded-xl border border-border p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Server className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">System Configuration</h2>
                    <p className="text-sm text-muted-foreground">Current runtime settings</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <ConfigItem icon={<Shield className="w-4 h-4" />} label="Environment" value={config?.environment || 'Unknown'} />
                  <ConfigItem icon={<Shield className="w-4 h-4" />} label="API Key Configured" value={config?.security.api_key_configured ? 'Yes' : 'No'} />
                  <ConfigItem icon={<Clock className="w-4 h-4" />} label="Rate Limit" value={`${config?.security.rate_limit_per_minute || 0} req/min`} />
                  <ConfigItem icon={<Clock className="w-4 h-4" />} label="Scheduler Timezone" value={config?.scheduler.timezone || 'UTC'} />
                  <ConfigItem icon={<Database className="w-4 h-4" />} label="Max Domains/Group" value={String(config?.monitoring.max_domains_per_group || 0)} />
                  <ConfigItem icon={<Database className="w-4 h-4" />} label="Snapshot Retention" value={`${config?.monitoring.snapshot_retention_days || 0} days`} />
                  <ConfigItem icon={<Monitor className="w-4 h-4" />} label="Screenshots" value={config?.monitoring.screenshot_enabled ? 'Enabled' : 'Disabled'} />
                  <ConfigItem icon={<Monitor className="w-4 h-4" />} label="Screenshot Size" value={`${config?.monitoring.screenshot_width || 0} x ${config?.monitoring.screenshot_height || 0}`} />
                  <ConfigItem icon={<Server className="w-4 h-4" />} label="Prometheus Metrics" value={config?.features.prometheus_enabled ? 'Enabled' : 'Disabled'} />
                  <ConfigItem icon={<Server className="w-4 h-4" />} label="Redis Cache" value={config?.features.redis_available ? 'Connected' : 'Not configured'} />
                </div>
              </div>

              {/* Appearance */}
              <div className="bg-card rounded-xl border border-border p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Settings2 className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Appearance</h2>
                    <p className="text-sm text-muted-foreground">Customize your dashboard theme</p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <button
                    onClick={() => setTheme('light')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${
                      resolvedTheme === 'light'
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border hover:bg-muted'
                    }`}
                  >
                    <Sun className="w-4 h-4" />
                    Light
                  </button>
                  <button
                    onClick={() => setTheme('dark')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${
                      resolvedTheme === 'dark'
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border hover:bg-muted'
                    }`}
                  >
                    <Moon className="w-4 h-4" />
                    Dark
                  </button>
                  <button
                    onClick={() => setTheme('system')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${
                      theme === 'system'
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border hover:bg-muted'
                    }`}
                  >
                    <Monitor className="w-4 h-4" />
                    System
                  </button>
                </div>
              </div>

              {/* Monitoring Defaults */}
              <div className="bg-card rounded-xl border border-border p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Clock className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Monitoring Defaults</h2>
                    <p className="text-sm text-muted-foreground">Default values for new domains</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <ConfigItem icon={<Clock className="w-4 h-4" />} label="Min Frequency" value={`${config?.monitoring.min_check_frequency_seconds || 0} seconds`} />
                  <ConfigItem icon={<Clock className="w-4 h-4" />} label="Default Timeout" value={`${config?.monitoring.default_timeout_seconds || 0} seconds`} />
                  <ConfigItem icon={<Database className="w-4 h-4" />} label="Max Concurrent Checks" value={String(config?.monitoring.max_concurrent_checks || 0)} />
                  <ConfigItem icon={<AlertTriangle className="w-4 h-4" />} label="Alert Threshold" value={String(config?.monitoring.alert_threshold || 0)} />
                </div>
              </div>
            </>
          )}

          {/* Danger Zone */}
          <div className="bg-card rounded-xl border-2 border-red-500/20 p-6">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0 mt-0.5" />
              <div>
                <h2 className="text-lg font-semibold text-foreground">Danger Zone</h2>
                <p className="text-sm text-muted-foreground mt-1">
                  Irreversible actions that will permanently delete data
                </p>
              </div>
            </div>

            <div className="bg-muted/50 rounded-lg p-4 space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <h3 className="font-medium text-foreground">Reset Environment</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Delete all monitoring groups, domains, snapshots, and logs. This action cannot be
                    undone.
                  </p>
                </div>
                <button
                  onClick={() => setShowConfirmDialog(true)}
                  disabled={isResetting}
                  className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
                >
                  <Trash2 className="w-4 h-4" />
                  Reset
                </button>
              </div>
            </div>
          </div>

          {/* Success Message */}
          {resetStats && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <RefreshCw className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-medium text-green-900">Environment Reset Successfully</h3>
                  <p className="text-sm text-green-700 mt-1">
                    Deleted {resetStats.groups_deleted} groups, {resetStats.domains_deleted} domains,
                    and {resetStats.snapshots_deleted} snapshots.
                  </p>
                  <p className="text-sm text-green-700 mt-2">Redirecting to home page...</p>
                </div>
              </div>
            </div>
          )}

          {/* Confirmation Dialog */}
          {showConfirmDialog && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
              <div className="bg-card rounded-xl border border-border shadow-lg max-w-md w-full p-6">
                <div className="flex items-start gap-3 mb-4">
                  <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0" />
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">Confirm Reset</h3>
                    <p className="text-sm text-muted-foreground mt-2">
                      Are you absolutely sure you want to reset the monitoring environment?
                    </p>
                    <p className="text-sm text-red-600 mt-2 font-medium">
                      This will permanently delete:
                    </p>
                    <ul className="text-sm text-muted-foreground mt-2 space-y-1 list-disc list-inside">
                      <li>All monitoring groups</li>
                      <li>All monitored domains</li>
                      <li>All snapshots and screenshots</li>
                      <li>All logs and history</li>
                    </ul>
                    <p className="text-sm text-red-600 mt-3 font-medium">
                      This action cannot be undone!
                    </p>
                  </div>
                </div>

                <div className="flex gap-3 mt-6">
                  <button
                    onClick={() => setShowConfirmDialog(false)}
                    disabled={isResetting}
                    className="flex-1 bg-muted hover:bg-muted/80 text-foreground font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleResetEnvironment}
                    disabled={isResetting}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {isResetting ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Resetting...
                      </>
                    ) : (
                      <>
                        <Trash2 className="w-4 h-4" />
                        Yes, Reset Everything
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ConfigItem({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 p-3 bg-muted/30 rounded-lg">
      <div className="text-muted-foreground">{icon}</div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide">{label}</p>
        <p className="text-sm font-medium text-foreground">{value}</p>
      </div>
    </div>
  )
}
