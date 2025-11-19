'use client'

import { useState } from 'react'
import { Play } from 'lucide-react'

interface AddMonitoringCardProps {
  onAddMonitoring: (domain: string, frequency: string, dumpMode: string) => void
}

export default function AddMonitoringCard({ onAddMonitoring }: AddMonitoringCardProps) {
  const [domain, setDomain] = useState('')
  const [frequencyValue, setFrequencyValue] = useState('1')
  const [frequencyUnit, setFrequencyUnit] = useState<'sec' | 'min' | 'hr'>('hr')
  const [dumpMode, setDumpMode] = useState<'html_only' | 'html_and_assets'>('html_only')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleStart = async () => {
    if (domain.trim() && !isSubmitting && frequencyValue) {
      let url = domain.trim()
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url
      }

      const frequency = `${frequencyValue} ${frequencyUnit}`

      setIsSubmitting(true)
      try {
        await onAddMonitoring(url, frequency, dumpMode)
        setDomain('')
        setFrequencyValue('1')
        setFrequencyUnit('hr')
      } catch (error) {
        console.error('Failed to add monitoring:', error)
      } finally {
        setIsSubmitting(false)
      }
    }
  }

  return (
    <div className="bg-card rounded-xl border border-border shadow-sm p-6">
      <h2 className="text-lg font-semibold text-foreground mb-4">Add Monitoring</h2>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-foreground mb-2">Domain URL</label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="https://example.com"
            className="w-full bg-input border border-border rounded-lg px-3 py-2 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
            disabled={isSubmitting}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-foreground mb-2">Check Frequency</label>
          <div className="flex gap-2">
            <input
              type="number"
              min="1"
              value={frequencyValue}
              onChange={(e) => setFrequencyValue(e.target.value)}
              className="w-20 bg-input border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-accent"
              disabled={isSubmitting}
            />
            <select
              value={frequencyUnit}
              onChange={(e) => setFrequencyUnit(e.target.value as 'sec' | 'min' | 'hr')}
              className="flex-1 bg-input border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-accent"
              disabled={isSubmitting}
            >
              <option value="sec">Seconds</option>
              <option value="min">Minutes</option>
              <option value="hr">Hours</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-foreground mb-2">Dump Mode</label>
          <select
            value={dumpMode}
            onChange={(e) => setDumpMode(e.target.value as 'html_only' | 'html_and_assets')}
            className="w-full bg-input border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-accent"
            disabled={isSubmitting}
          >
            <option value="html_only">HTML Only</option>
            <option value="html_and_assets">HTML + Assets</option>
          </select>
        </div>
      </div>

      <button
        onClick={handleStart}
        disabled={isSubmitting || !domain.trim() || !frequencyValue || parseInt(frequencyValue) < 1}
        className="mt-4 w-full md:w-auto bg-accent hover:bg-accent/90 text-accent-foreground font-medium py-2 px-6 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <Play className="w-4 h-4" />
        {isSubmitting ? 'Starting...' : 'Start Monitoring'}
      </button>
    </div>
  )
}
