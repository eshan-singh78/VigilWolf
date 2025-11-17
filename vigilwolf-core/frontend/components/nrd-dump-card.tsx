'use client'

import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { getApiUrl, API_ENDPOINTS } from '@/lib/api'

export default function NrdDumpCard() {
  const [isDumping, setIsDumping] = useState(false)
  const [dumpText, setDumpText] = useState('')
  const [isExpanded, setIsExpanded] = useState(false)
  const [status, setStatus] = useState<'Idle' | 'Dumping' | 'Done'>('Idle')

  const handleDump = async () => {
    setStatus('Dumping')
    setIsDumping(true)

    try {
      const res = await fetch(getApiUrl(API_ENDPOINTS.DUMP_NRD))
      if (!res.ok) throw new Error(`Request failed: ${res.status}`)

      const data = await res.json()
      if (data?.output) setDumpText(data.output)
      setStatus('Done')
    } catch (err) {
      setStatus('Done')
      console.error('NRD dump failed', err)
    } finally {
      setIsDumping(false)
    }
  }

  return (
    <div className="bg-card rounded-xl border border-border shadow-sm hover:shadow-md transition-shadow">
      <div className="p-6 border-b border-border">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Newly Registered Domains (NRDs)</h2>
            <p className="text-sm text-muted-foreground mt-2">Extract newly registered domains from monitoring sources</p>
          </div>
          <span className={`px-3 py-1 rounded-full text-xs font-medium ${
            status === 'Idle' ? 'bg-muted text-muted-foreground' :
            status === 'Dumping' ? 'bg-accent/20 text-accent' :
            'bg-green-100 text-green-700'
          }`}>
            {status}
          </span>
        </div>
      </div>

      <div className="p-6 space-y-4">
        <button
          onClick={handleDump}
          disabled={isDumping}
          className="w-full bg-accent hover:bg-accent/90 disabled:bg-accent/50 text-accent-foreground font-medium py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${isDumping ? 'animate-spin' : ''}`} />
          {isDumping ? 'Dumping...' : 'Dump NRDs'}
        </button>

        <div className="relative">
          <textarea
            readOnly
            value={dumpText}
            placeholder="Logs will be shown here"
            className={`w-full ${isExpanded ? 'h-96' : 'h-32'} bg-muted rounded-lg border border-border p-3 font-mono text-sm text-foreground resize-none`}
          />
          <div className="absolute top-2 right-2 bg-white px-2 py-1 rounded-md shadow">
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-xs transition-colors"
              title={isExpanded ? 'Collapse' : 'Expand'}
            >
              {isExpanded ? 'Collapse' : 'Expand'}
            </button>
          </div>
        </div>
      </div>

      {status === 'Dumping' && (
        <div className="h-1 bg-border rounded-b-xl overflow-hidden">
          <div className="h-full bg-accent animate-pulse" style={{ width: '70%' }} />
        </div>
      )}
    </div>
  )
}

