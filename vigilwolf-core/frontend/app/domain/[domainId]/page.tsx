'use client'

import { useEffect, useState, useRef } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { ArrowLeft, Download, RefreshCw } from 'lucide-react'
import { getApiUrl, API_ENDPOINTS } from '@/lib/api'

interface Snapshot {
  id: string
  timestamp: string
  trigger_type: string
  success: boolean
  asset_count: number
  has_screenshot: boolean
  error_message?: string
}

interface SnapshotDetails {
  snapshot: {
    id: string
    timestamp: string
    trigger_type: string
    success: boolean
    html_path: string
    screenshot_path?: string
    assets_dir?: string
    asset_count: number
  }
  domain: {
    id: string
    url: string
    dump_mode: string
    frequency_seconds: number
  }
  html_content?: string
  screenshot_exists: boolean
  assets: string[]
  ping_logs: Array<{
    timestamp: string
    reachable: boolean
    status_code?: number
    change_detected: boolean
    message: string
  }>
  dump_logs: Array<{
    timestamp: string
    trigger_type: string
    snapshot_id?: string
    success: boolean
    error_message?: string
    message: string
  }>
}

export default function DomainDetailsPage() {
  const params = useParams()
  const router = useRouter()
  const domainId = params.domainId as string

  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [selectedSnapshot, setSelectedSnapshot] = useState<SnapshotDetails | null>(null)
  const [domainUrl, setDomainUrl] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [triggering, setTriggering] = useState(false)
  
  const selectedSnapshotRef = useRef<string | null>(null)
  const isInitialLoadRef = useRef(true)

  useEffect(() => {
    selectedSnapshotRef.current = selectedSnapshot?.snapshot.id || null
  }, [selectedSnapshot])

  useEffect(() => {
    fetchSnapshots(true) // Initial load
    
    const interval = setInterval(() => {
      fetchSnapshots(false) // Background refresh
      if (selectedSnapshotRef.current) {
        fetchSnapshotDetails(selectedSnapshotRef.current, false)
      }
    }, 10000)
    
    return () => clearInterval(interval)
  }, [domainId])

  const fetchSnapshots = async (showLoading = true) => {
    try {
      if (showLoading) {
        setLoading(true)
      }
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_DOMAIN_SNAPSHOTS(domainId)))
      if (!response.ok) throw new Error('Failed to fetch snapshots')
      
      const data = await response.json()
      setSnapshots(data.snapshots || [])
      setDomainUrl(data.domain_url || '')
      
      // Auto-select the latest snapshot only on initial load
      if (isInitialLoadRef.current && data.snapshots && data.snapshots.length > 0) {
        await fetchSnapshotDetails(data.snapshots[data.snapshots.length - 1].id, showLoading)
        isInitialLoadRef.current = false
      }
    } catch (error) {
      console.error('Error fetching snapshots:', error)
    } finally {
      if (showLoading) {
        setLoading(false)
      }
    }
  }

  const fetchSnapshotDetails = async (snapshotId: string, showLoading = true) => {
    try {
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_SNAPSHOT_DETAILS(snapshotId)))
      if (!response.ok) throw new Error('Failed to fetch snapshot details')
      
      const data = await response.json()
      setSelectedSnapshot(data)
    } catch (error) {
      console.error('Error fetching snapshot details:', error)
    }
  }

  const triggerForceDump = async () => {
    try {
      setTriggering(true)
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_FORCE_DUMP(domainId)), {
        method: 'POST'
      })
      if (!response.ok) throw new Error('Failed to trigger force dump')
      
      // Refresh snapshots after a short delay (without showing loading state)
      setTimeout(() => fetchSnapshots(false), 3000)
    } catch (error) {
      console.error('Error triggering force dump:', error)
      alert('Failed to trigger force dump. Please try again.')
    } finally {
      setTriggering(false)
    }
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  const formatFrequency = (seconds: number): string => {
    if (seconds < 60) return `${seconds} seconds`
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`
    return `${Math.floor(seconds / 3600)} hours`
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-background p-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center py-12">
            <p className="text-muted-foreground">Loading domain details...</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => router.back()}
              className="p-2 hover:bg-muted rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-foreground">Domain Monitoring</h1>
                <span className="text-xs text-muted-foreground">(Auto-refresh: 10s)</span>
              </div>
              <p className="text-muted-foreground mt-1">{domainUrl}</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => {
                fetchSnapshots(false)
                if (selectedSnapshot) {
                  fetchSnapshotDetails(selectedSnapshot.snapshot.id, false)
                }
              }}
              className="bg-muted hover:bg-muted/80 text-foreground font-medium py-2 px-4 rounded-lg transition-colors flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            <button
              onClick={triggerForceDump}
              disabled={triggering}
              className="bg-accent hover:bg-accent/90 text-accent-foreground font-medium py-2 px-4 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {triggering ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Capturing...
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  Force Dump
                </>
              )}
            </button>
          </div>
        </div>

        {/* Domain Info */}
        {selectedSnapshot && (
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Domain Information</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">URL</p>
                <p className="text-foreground font-mono">{selectedSnapshot.domain.url}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Dump Mode</p>
                <p className="text-foreground">{selectedSnapshot.domain.dump_mode.replace('_', ' ')}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Check Frequency</p>
                <p className="text-foreground">{formatFrequency(selectedSnapshot.domain.frequency_seconds)}</p>
              </div>
            </div>
          </div>
        )}

        {/* Snapshots Grid */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">
            Snapshots ({snapshots.length})
          </h2>
          {snapshots.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No snapshots yet. Click "Force Dump" to create one.
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {snapshots.map((snap) => (
                <button
                  key={snap.id}
                  onClick={() => fetchSnapshotDetails(snap.id)}
                  className={`bg-muted rounded-lg border-2 p-3 hover:border-accent transition-all text-left ${
                    selectedSnapshot?.snapshot.id === snap.id ? 'border-accent' : 'border-transparent'
                  }`}
                >
                  <div className="aspect-video bg-border rounded mb-2 flex items-center justify-center overflow-hidden">
                    {snap.has_screenshot ? (
                      <span className="text-xs text-muted-foreground">📸</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No Screenshot</span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground truncate">
                    {snap.trigger_type === 'scheduled' ? '⏰ Scheduled' : '👆 Manual'}
                  </p>
                  <p className="text-xs text-foreground font-mono mt-1 truncate">
                    {new Date(snap.timestamp).toLocaleTimeString()}
                  </p>
                  <p className="text-xs mt-1">
                    {snap.success ? (
                      <span className="text-green-600">✓ Success</span>
                    ) : (
                      <span className="text-red-600">✗ Failed</span>
                    )}
                  </p>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Selected Snapshot Details */}
        {selectedSnapshot && (
          <>
            {/* Screenshot Section */}
            {selectedSnapshot.screenshot_exists && selectedSnapshot.snapshot.screenshot_path && (
              <div className="bg-card rounded-xl border border-border p-6">
                <h2 className="text-lg font-semibold text-foreground mb-4">Screenshot</h2>
                <div className="bg-muted rounded-lg p-4">
                  <img
                    src={getApiUrl(API_ENDPOINTS.MONITORING_SNAPSHOT_SCREENSHOT(selectedSnapshot.snapshot.id))}
                    alt="Domain screenshot"
                    className="w-full rounded border border-border"
                    onError={(e) => {
                      e.currentTarget.style.display = 'none'
                      console.error('Failed to load screenshot')
                    }}
                  />
                </div>
              </div>
            )}

            {/* HTML Content */}
            <div className="bg-card rounded-xl border border-border p-6">
              <h2 className="text-lg font-semibold text-foreground mb-4">HTML Content</h2>
              <div className="bg-muted rounded-lg p-4 max-h-96 overflow-auto">
                <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                  {selectedSnapshot.html_content || 'No HTML content available'}
                </pre>
              </div>
            </div>

            {/* Assets */}
            {selectedSnapshot.assets.length > 0 && (
              <div className="bg-card rounded-xl border border-border p-6">
                <h2 className="text-lg font-semibold text-foreground mb-4">
                  Assets ({selectedSnapshot.assets.length})
                </h2>
                <div className="bg-muted rounded-lg p-4 max-h-64 overflow-auto">
                  <ul className="space-y-1">
                    {selectedSnapshot.assets.map((asset, idx) => (
                      <li key={idx} className="text-xs font-mono text-muted-foreground">
                        {asset}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Logs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Ping Logs */}
              <div className="bg-card rounded-xl border border-border p-6">
                <h2 className="text-lg font-semibold text-foreground mb-4">Ping Logs</h2>
                <div className="space-y-2 max-h-96 overflow-auto">
                  {selectedSnapshot.ping_logs.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No ping logs available</p>
                  ) : (
                    selectedSnapshot.ping_logs.map((log, idx) => (
                      <div key={idx} className="bg-muted rounded-lg p-3">
                        <p className="text-xs font-mono text-foreground">
                          {formatTimestamp(log.timestamp)}
                        </p>
                        <p className="text-sm text-muted-foreground mt-1">{log.message}</p>
                        <div className="flex gap-2 mt-2 text-xs">
                          <span className={log.reachable ? 'text-green-600' : 'text-red-600'}>
                            {log.reachable ? '✓ Reachable' : '✗ Unreachable'}
                          </span>
                          {log.status_code && (
                            <span className="text-muted-foreground">Status: {log.status_code}</span>
                          )}
                          {log.change_detected && (
                            <span className="text-orange-600">⚠ Change Detected</span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Dump Logs */}
              <div className="bg-card rounded-xl border border-border p-6">
                <h2 className="text-lg font-semibold text-foreground mb-4">Dump Logs</h2>
                <div className="space-y-2 max-h-96 overflow-auto">
                  {selectedSnapshot.dump_logs.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No dump logs available</p>
                  ) : (
                    selectedSnapshot.dump_logs.map((log, idx) => (
                      <div key={idx} className="bg-muted rounded-lg p-3">
                        <p className="text-xs font-mono text-foreground">
                          {formatTimestamp(log.timestamp)}
                        </p>
                        <p className="text-sm text-muted-foreground mt-1">{log.message}</p>
                        <div className="flex gap-2 mt-2 text-xs">
                          <span className={log.success ? 'text-green-600' : 'text-red-600'}>
                            {log.success ? '✓ Success' : '✗ Failed'}
                          </span>
                          {log.trigger_type && (
                            <span className="text-muted-foreground">{log.trigger_type}</span>
                          )}
                        </div>
                        {log.error_message && (
                          <p className="text-xs text-red-600 mt-2 font-mono">{log.error_message}</p>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
