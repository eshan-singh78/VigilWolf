'use client'

import Navbar from '@/components/navbar'
import MonitoringDashboard from '@/components/monitoring-dashboard'

export default function MonitorPage() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-20">
        <MonitoringDashboard />
      </main>
    </div>
  )
}
