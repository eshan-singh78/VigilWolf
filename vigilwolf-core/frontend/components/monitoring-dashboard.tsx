'use client'

import { useState, useEffect } from 'react'
import AddMonitoringCard from './add-monitoring-card'
import MonitoringListTable from './monitoring-list-table'
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

export default function MonitoringDashboard() {
  const [monitoredDomains, setMonitoredDomains] = useState<MonitoredDomain[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchDomains = async (showLoading = true) => {
    try {
      if (showLoading) {
        setLoading(true)
      }
      setError(null)
      
      // Fetch all groups
      const groupsResponse = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_GROUPS))
      if (!groupsResponse.ok) throw new Error('Failed to fetch groups')
      const groupsData = await groupsResponse.json()
      
      // Fetch domains for each group
      const allDomains: MonitoredDomain[] = []
      for (const group of groupsData.groups) {
        const domainsResponse = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_GROUP_DOMAINS(group.id)))
        if (!domainsResponse.ok) continue
        
        const domainsData = await domainsResponse.json()
        
        for (const domain of domainsData.domains) {
          allDomains.push({
            id: domain.id,
            domain: domain.url,
            frequency: formatFrequency(domain.frequency_seconds),
            baselineStatus: domain.last_checked_at ? 'Done' : 'Pending',
            lastCheck: domain.last_checked_at ? formatLastCheck(domain.last_checked_at) : 'Never',
            changeDetected: false, // TODO: Implement change detection
            groupId: group.id
          })
        }
      }
      
      setMonitoredDomains(allDomains)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load domains')
      console.error('Error fetching domains:', err)
    } finally {
      if (showLoading) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    fetchDomains(true) // Initial load with loading state
    
    // Auto-refresh every 10 seconds without showing loading state
    const interval = setInterval(() => {
      fetchDomains(false)
    }, 10000)
    
    return () => clearInterval(interval)
  }, [])

  const addMonitoring = async (domain: string, frequency: string, dumpMode: string) => {
    try {
      const frequencySeconds = parseFrequency(frequency)
      
      const response = await fetch(getApiUrl(API_ENDPOINTS.MONITORING_GROUPS), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Group for ${domain}`,
          domains: [{
            url: domain,
            dump_mode: dumpMode,
            frequency_seconds: frequencySeconds
          }]
        })
      })
      
      if (!response.ok) throw new Error('Failed to create monitoring group')
      
      // Refresh the list without showing loading state
      await fetchDomains(false)
    } catch (err) {
      console.error('Error adding monitoring:', err)
      alert('Failed to add monitoring. Please try again.')
    }
  }

  const formatFrequency = (seconds: number): string => {
    if (seconds < 60) return `${seconds} sec`
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min`
    return `${Math.floor(seconds / 3600)} hr`
  }

  const parseFrequency = (frequency: string): number => {
    const match = frequency.match(/(\d+)\s*(sec|min|hr)/)
    if (!match) return 3600 // default 1 hour
    
    const value = parseInt(match[1])
    const unit = match[2]
    
    if (unit === 'sec') return value
    if (unit === 'min') return value * 60
    return value * 3600
  }

  const formatLastCheck = (timestamp: string): string => {
    const date = new Date(timestamp)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins} min ago`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hr ago`
    return `${Math.floor(diffMins / 1440)} days ago`
  }

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="text-center py-12">
          <p className="text-muted-foreground">Loading monitoring data...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="text-center py-12">
          <p className="text-red-600">Error: {error}</p>
          <button 
            onClick={() => fetchDomains(true)}
            className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded hover:bg-primary/90"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="space-y-6">
        <AddMonitoringCard onAddMonitoring={addMonitoring} />
        <MonitoringListTable domains={monitoredDomains} />
      </div>
    </div>
  )
}
