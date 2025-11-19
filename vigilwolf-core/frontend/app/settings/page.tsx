'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { AlertTriangle, Trash2, RefreshCw } from 'lucide-react'
import { getApiUrl, API_ENDPOINTS } from '@/lib/api'
import Navbar from '@/components/navbar'

export default function SettingsPage() {
  const router = useRouter()
  const [isResetting, setIsResetting] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [resetStats, setResetStats] = useState<{
    groups_deleted: number
    domains_deleted: number
    snapshots_deleted: number
  } | null>(null)

  const handleResetEnvironment = async () => {
    try {
      setIsResetting(true)
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_RESET), {
        method: 'POST'
      })

      if (!response.ok) {
        throw new Error('Failed to reset environment')
      }

      const data = await response.json()
      setResetStats(data.statistics)
      setShowConfirmDialog(false)

      // Redirect to home page after a short delay
      setTimeout(() => {
        router.push('/')
      }, 3000)
    } catch (error) {
      console.error('Error resetting environment:', error)
      alert('Failed to reset environment. Please try again.')
    } finally {
      setIsResetting(false)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="p-6 pt-24">
        <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-foreground">Settings</h1>
          <p className="text-muted-foreground mt-1">
            Manage your monitoring system configuration
          </p>
        </div>

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
