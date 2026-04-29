'use client'

import Navbar from '@/components/navbar'
import NrdDashboard from '@/components/nrd-dashboard'

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-20">
        <NrdDashboard />
      </main>
    </div>
  )
}
