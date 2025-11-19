'use client'

import { useState } from 'react'
import { RefreshCw, Eye } from 'lucide-react'
import NrdDumpCard from './nrd-dump-card'
import BrandSearchCard from './brand-search-card'
import WhoisModal from './whois-modal'

interface DomainResult {
  domain: string
  fuzzyScore: number
  regexHit: boolean
}

interface WhoisData {
  domain: string
}

export default function NrdDashboard() {
  const [selectedDomain, setSelectedDomain] = useState<WhoisData | null>(null)
  const [dummyResults] = useState<DomainResult[]>([
    { domain: 'example-security.com', fuzzyScore: 94, regexHit: true },
    { domain: 'example-secure.io', fuzzyScore: 87, regexHit: false },
    { domain: 'examplesec.net', fuzzyScore: 76, regexHit: true },
  ])

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
