'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { X, ChevronDown, Download, ArrowLeft } from 'lucide-react'
import { getApiUrl, API_ENDPOINTS } from '@/lib/api'

interface MonitoredDomain {
  id: string
  domain: string
  frequency: string
  baselineStatus: 'Done' | 'Pending'
  lastCheck: string
  changeDetected: boolean
  groupId: string
}

interface ExploreModalProps {
  domain: MonitoredDomain
  onClose: () => void
}

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

export default function ExploreModal({ domain, onClose }: ExploreModalProps) {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<'logs' | 'snapshots' | 'dumps'>('snapshots')
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [selectedSnapshot, setSelectedSnapshot] = useState<SnapshotDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [expandedLog, setExpandedLog] = useState<string | null>(null)

  const tabs = [
    { id: 'snapshots', label: 'Snapshots' },
    { id: 'logs', label: 'Logs' },
    { id: 'dumps', label: 'Source Dumps' },
  ] as const

  const handleBackToMonitor = () => {
    router.push('/monitor')
  }

  useEffect(() => {
    fetchSnapshots()
  }, [domain.id])

  const fetchSnapshots = async () => {
    try {
      setLoading(true)
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_DOMAIN_SNAPSHOTS(domain.id)))
      if (!response.ok) throw new Error('Failed to fetch snapshots')
      
      const data = await response.json()
      setSnapshots(data.snapshots || [])
    } catch (error) {
      console.error('Error fetching snapshots:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchSnapshotDetails = async (snapshotId: string) => {
    try {
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_SNAPSHOT_DETAILS(snapshotId)))
      if (!response.ok) throw new Error('Failed to fetch snapshot details')
      
      const data = await response.json()
      setSelectedSnapshot(data)
      setActiveTab('dumps')
    } catch (error) {
      console.error('Error fetching snapshot details:', error)
    }
  }

  const triggerForceDump = async () => {
    try {
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_FORCE_DUMP(domain.id)), {
        method: 'POST'
      })
      if (!response.ok) throw new Error('Failed to trigger force dump')
      
      // Refresh snapshots after a short delay
      setTimeout(fetchSnapshots, 2000)
    } catch (error) {
      console.error('Error triggering force dump:', error)
      alert('Failed to trigger force dump. Please try again.')
    }
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-xl border border-border shadow-lg max-w-4xl w-full max-h-96 overflow-auto">
        <div className="flex items-center justify-between p-6 border-b border-border sticky top-0 bg-card">
          <div className="flex items-center gap-3">
            <button 
              onClick={handleBackToMonitor} 
              className="p-1 hover:bg-muted rounded transition-colors"
              title="Back to Monitor"
            >
              <ArrowLeft className="w-5 h-5 text-muted-foreground" />
            </button>
            <div>
              <h2 className="text-lg font-semibold text-foreground">Explore Monitoring Data</h2>
              <p className="text-sm text-muted-foreground mt-1">{domain.domain}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-border rounded transition-colors">
            <X className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-border flex">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="p-6 space-y-3 max-h-80 overflow-y-auto">
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : (
            <>
              {activeTab === 'snapshots' && (
                <div className="space-y-4">
                  <button
                    onClick={triggerForceDump}
                    className="w-full bg-accent hover:bg-accent/90 text-accent-foreground font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Trigger Force Dump
                  </button>
                  
                  {snapshots.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      No snapshots yet. Click "Trigger Force Dump" to create one.
                    </div>
                  ) : (
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      {snapshots.map((snap) => (
                        <button
                          key={snap.id}
                          onClick={() => fetchSnapshotDetails(snap.id)}
                          className="bg-muted rounded-lg border border-border p-3 shadow-sm hover:shadow-md transition-shadow text-left"
                        >
                          <div className="aspect-video bg-border rounded mb-2 flex items-center justify-center">
                            {snap.has_screenshot ? (
                              <span className="text-xs text-muted-foreground">Screenshot</span>
                            ) : (
                              <span className="text-xs text-muted-foreground">No Screenshot</span>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {snap.trigger_type === 'scheduled' ? 'Scheduled' : 'Manual'}
                          </p>
                          <p className="text-xs text-foreground font-mono mt-1">
                            {formatTimestamp(snap.timestamp)}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
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
              )}

              {activeTab === 'logs' && selectedSnapshot && (
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-2">Ping Logs</h3>
                    <div className="space-y-2">
                      {selectedSnapshot.ping_logs.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No ping logs available</p>
                      ) : (
                        selectedSnapshot.ping_logs.map((log, idx) => (
                          <div key={idx} className="border border-border rounded-lg">
                            <button
                              onClick={() => setExpandedLog(expandedLog === `ping-${idx}` ? null : `ping-${idx}`)}
                              className="w-full px-4 py-3 flex items-center justify-between hover:bg-muted/50 transition-colors"
                            >
                              <div className="text-left">
                                <p className="text-sm font-mono text-foreground">
                                  [{formatTimestamp(log.timestamp)}] {log.message}
                                </p>
                                <p className="text-xs text-muted-foreground mt-1">
                                  {log.reachable ? '✓ Reachable' : '✗ Unreachable'}
                                  {log.status_code && ` | Status: ${log.status_code}`}
                                  {log.change_detected && ' | Change Detected'}
                                </p>
                              </div>
                              <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${expandedLog === `ping-${idx}` ? 'rotate-180' : ''}`} />
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-2">Dump Logs</h3>
                    <div className="space-y-2">
                      {selectedSnapshot.dump_logs.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No dump logs available</p>
                      ) : (
                        selectedSnapshot.dump_logs.map((log, idx) => (
                          <div key={idx} className="border border-border rounded-lg">
                            <button
                              onClick={() => setExpandedLog(expandedLog === `dump-${idx}` ? null : `dump-${idx}`)}
                              className="w-full px-4 py-3 flex items-center justify-between hover:bg-muted/50 transition-colors"
                            >
                              <div className="text-left">
                                <p className="text-sm font-mono text-foreground">
                                  [{formatTimestamp(log.timestamp)}] {log.message}
                                </p>
                                <p className="text-xs text-muted-foreground mt-1">
                                  {log.success ? '✓ Success' : '✗ Failed'}
                                  {log.trigger_type && ` | ${log.trigger_type}`}
                                </p>
                              </div>
                              <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${expandedLog === `dump-${idx}` ? 'rotate-180' : ''}`} />
                            </button>
                            {expandedLog === `dump-${idx}` && log.error_message && (
                              <div className="px-4 py-3 border-t border-border bg-muted/30 text-xs font-mono text-red-600">
                                {log.error_message}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'dumps' && selectedSnapshot && (
                <div className="space-y-3">
                  <div className="border border-border rounded-lg">
                    <div className="px-4 py-3 bg-muted/30">
                      <p className="text-sm font-semibold text-foreground">HTML Content</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Path: {selectedSnapshot.snapshot.html_path}
                      </p>
                    </div>
                    <div className="px-4 py-3 border-t border-border bg-muted text-xs font-mono text-muted-foreground max-h-64 overflow-y-auto">
                      {selectedSnapshot.html_content ? (
                        <pre className="whitespace-pre-wrap">{selectedSnapshot.html_content.substring(0, 2000)}...</pre>
                      ) : (
                        <p>No HTML content available</p>
                      )}
                    </div>
                  </div>

                  {selectedSnapshot.assets.length > 0 && (
                    <div className="border border-border rounded-lg">
                      <div className="px-4 py-3 bg-muted/30">
                        <p className="text-sm font-semibold text-foreground">Assets ({selectedSnapshot.assets.length})</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Directory: {selectedSnapshot.snapshot.assets_dir}
                        </p>
                      </div>
                      <div className="px-4 py-3 border-t border-border max-h-40 overflow-y-auto">
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
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
