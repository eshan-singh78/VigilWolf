'use client'

import { useState } from 'react'
import { Play } from 'lucide-react'

interface AddMonitoringCardProps {
  onAddMonitoring: (domain: string, frequency: string) => void
}

export default function AddMonitoringCard({ onAddMonitoring }: AddMonitoringCardProps) {
  const [domain, setDomain] = useState('')
  const [frequency, setFrequency] = useState('1 hr')
  const [batchMode, setBatchMode] = useState(false)

  const handleStart = () => {
    if (domain.trim()) {
      onAddMonitoring(domain, frequency)
      setDomain('')
    }
  }

  return (
    <div className="bg-card rounded-xl border border-border shadow-sm p-6">
      <h2 className="text-lg font-semibold text-foreground mb-4">Add Monitoring</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-foreground mb-2">Domain Name</label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="w-full bg-input border border-border rounded-lg px-3 py-2 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-foreground mb-2">Frequency</label>
          <select
            value={frequency}
            onChange={(e) => setFrequency(e.target.value)}
            className="w-full bg-input border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-accent"
          >
            <option>30 min</option>
            <option>1 hr</option>
            <option>6 hr</option>
            <option>24 hr</option>
          </select>
        </div>

        <div className="flex items-end">
          <label className="flex items-center gap-2 cursor-pointer text-sm text-muted-foreground hover:text-foreground transition-colors">
            <input
              type="checkbox"
              checked={batchMode}
              onChange={(e) => setBatchMode(e.target.checked)}
              className="w-4 h-4"
            />
            Batch Mode
          </label>
        </div>
      </div>

      <button
        onClick={handleStart}
        className="mt-4 w-full md:w-auto bg-accent hover:bg-accent/90 text-accent-foreground font-medium py-2 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
      >
        <Play className="w-4 h-4" />
        Start Monitoring
      </button>
    </div>
  )
}
