'use client'

import { useState } from 'react'
import { RefreshCw, Eye } from 'lucide-react'
import NrdDumpCard from './nrd-dump-card'
import BrandSearchCard from './brand-search-card'
import WhoisModal from './whois-modal'

interface WhoisData {
  domain: string
}

export default function NrdDashboard() {
  const [selectedDomain, setSelectedDomain] = useState<WhoisData | null>(null)

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <NrdDumpCard />
        <BrandSearchCard onViewWhois={(domain) => setSelectedDomain({ domain })} />
      </div>

      {selectedDomain && (
        <WhoisModal domain={selectedDomain.domain} onClose={() => setSelectedDomain(null)} />
      )}
    </div>
  )
}
