'use client'

import { useState } from 'react'
import AddMonitoringCard from './add-monitoring-card'
import MonitoringListTable from './monitoring-list-table'
import ExploreModal from './explore-modal'

interface MonitoredDomain {
  id: string
  domain: string
  frequency: string
  baselineStatus: 'Done' | 'Pending'
  lastCheck: string
  changeDetected: boolean
}

export default function MonitoringDashboard() {
  const [monitoredDomains, setMonitoredDomains] = useState<MonitoredDomain[]>([
    { id: '1', domain: 'company.com', frequency: '1 hr', baselineStatus: 'Done', lastCheck: '5 min ago', changeDetected: false },
    { id: '2', domain: 'brand-security.io', frequency: '6 hr', baselineStatus: 'Done', lastCheck: '2 hr ago', changeDetected: true },
    { id: '3', domain: 'example-monitor.net', frequency: '30 min', baselineStatus: 'Pending', lastCheck: 'Never', changeDetected: false },
  ])
  const [selectedDomain, setSelectedDomain] = useState<MonitoredDomain | null>(null)

  const addMonitoring = (domain: string, frequency: string) => {
    const newDomain: MonitoredDomain = {
      id: Date.now().toString(),
      domain,
      frequency,
      baselineStatus: 'Pending',
      lastCheck: 'Never',
      changeDetected: false,
    }
    setMonitoredDomains([...monitoredDomains, newDomain])
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="space-y-6">
        <AddMonitoringCard onAddMonitoring={addMonitoring} />
        <MonitoringListTable domains={monitoredDomains} onExplore={setSelectedDomain} />
      </div>

      {selectedDomain && (
        <ExploreModal domain={selectedDomain} onClose={() => setSelectedDomain(null)} />
      )}
    </div>
  )
}
