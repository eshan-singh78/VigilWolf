'use client'

import { useState } from 'react'
import Navbar from '@/components/navbar'
import NrdDashboard from '@/components/nrd-dashboard'
import MonitoringDashboard from '@/components/monitoring-dashboard'

export default function Home() {
  const [activeTab, setActiveTab] = useState<'home' | 'monitoring'>('home')

  return (
    <div className="min-h-screen bg-background">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <main className="pt-20">
        {activeTab === 'home' && <NrdDashboard />}
        {activeTab === 'monitoring' && <MonitoringDashboard />}
      </main>
    </div>
  )
}
