'use client'

import { useState } from 'react'
import { X, ChevronDown } from 'lucide-react'

interface MonitoredDomain {
  id: string
  domain: string
  frequency: string
  baselineStatus: 'Done' | 'Pending'
  lastCheck: string
  changeDetected: boolean
}

interface ExploreModalProps {
  domain: MonitoredDomain
  onClose: () => void
}

export default function ExploreModal({ domain, onClose }: ExploreModalProps) {
  const [activeTab, setActiveTab] = useState<'logs' | 'snapshots' | 'dumps' | 'diff'>('logs')
  const [expandedLog, setExpandedLog] = useState<number | null>(null)

  const tabs = [
    { id: 'logs', label: 'Logs' },
    { id: 'snapshots', label: 'Snapshots' },
    { id: 'dumps', label: 'Source Dumps' },
    { id: 'diff', label: 'Diff Viewer' },
  ] as const

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-xl border border-border shadow-lg max-w-4xl w-full max-h-96 overflow-auto">
        <div className="flex items-center justify-between p-6 border-b border-border sticky top-0 bg-card">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Explore Monitoring Data</h2>
            <p className="text-sm text-muted-foreground mt-1">{domain.domain}</p>
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
          {activeTab === 'logs' && (
            <div className="space-y-2">
              {[1, 2, 3].map((log) => (
                <div key={log} className="border border-border rounded-lg">
                  <button
                    onClick={() => setExpandedLog(expandedLog === log ? null : log)}
                    className="w-full px-4 py-3 flex items-center justify-between hover:bg-muted/50 transition-colors"
                  >
                    <div className="text-left">
                      <p className="text-sm font-mono text-foreground">[2024-11-16 {14 + log}:30:00] Page snapshot taken</p>
                      <p className="text-xs text-muted-foreground mt-1">Status: 200 OK | Size: {50 + log * 10}KB</p>
                    </div>
                    <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${expandedLog === log ? 'rotate-180' : ''}`} />
                  </button>
                  {expandedLog === log && (
                    <div className="px-4 py-3 border-t border-border bg-muted/30 text-xs font-mono text-muted-foreground">
                      <p>HTTP/1.1 200 OK</p>
                      <p>Content-Type: text/html; charset=utf-8</p>
                      <p>Content-Length: {50 + log * 10}000</p>
                      <p>Cache-Control: max-age=3600</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'snapshots' && (
            <div className="grid grid-cols-3 gap-3">
              {[1, 2, 3].map((snap) => (
                <div key={snap} className="bg-muted rounded-lg border border-border p-3 shadow-sm hover:shadow-md transition-shadow">
                  <div className="aspect-video bg-border rounded mb-2" />
                  <p className="text-xs text-muted-foreground text-center">Snapshot #{snap}</p>
                  <p className="text-xs text-foreground text-center font-mono mt-1">2024-11-16 {14 + snap}:00</p>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'dumps' && (
            <div className="space-y-3">
              {['HTML', 'CSS', 'JavaScript'].map((type) => (
                <div key={type} className="border border-border rounded-lg">
                  <button className="w-full px-4 py-3 flex items-center justify-between hover:bg-muted/50 transition-colors">
                    <p className="text-sm font-semibold text-foreground">{type}</p>
                    <ChevronDown className="w-4 h-4 text-muted-foreground" />
                  </button>
                  <div className="px-4 py-3 border-t border-border bg-muted text-xs font-mono text-muted-foreground max-h-24 overflow-y-auto">
                    &lt;!DOCTYPE html&gt;<br/>
                    &lt;html&gt;<br/>
                    &lt;head&gt;<br/>
                    &lt;title&gt;Example&lt;/title&gt;<br/>
                    &lt;/head&gt;
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'diff' && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs font-semibold text-foreground mb-2">Previous Version</p>
                  <div className="bg-muted rounded p-3 font-mono text-xs text-muted-foreground max-h-40 overflow-y-auto border border-border">
                    &lt;h1&gt;Welcome&lt;/h1&gt;<br/>
                    &lt;p&gt;Old content&lt;/p&gt;
                  </div>
                </div>
                <div>
                  <p className="text-xs font-semibold text-foreground mb-2">Current Version</p>
                  <div className="bg-muted rounded p-3 font-mono text-xs text-muted-foreground max-h-40 overflow-y-auto border border-border">
                    &lt;h1&gt;Welcome&lt;/h1&gt;<br/>
                    <span className="bg-green-100 text-green-700">&lt;p&gt;New content&lt;/p&gt;</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
