'use client'

import { useState } from 'react'
import { Search, Eye } from 'lucide-react'
import { getApiUrl, API_ENDPOINTS } from '@/lib/api'

interface DomainResult {
  domain: string
  fuzzyScore: number
  regexHit: boolean
}

interface BrandSearchCardProps {
  onViewWhois?: (domain: string) => void
}

export default function BrandSearchCard({ onViewWhois }: BrandSearchCardProps) {
  const [brandName, setBrandName] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [domains, setDomains] = useState<string[]>([])
  const [filename, setFilename] = useState('')
  const [showFile, setShowFile] = useState(false)
  const [results, setResults] = useState<DomainResult[]>([])

  const handleShowFile = async () => {
    try {
      const res = await fetch(getApiUrl(API_ENDPOINTS.NRD_LATEST))
      if (!res.ok) return
      const data = await res.json()
      setFilename(data.filename || '')
      setDomains(data.domains || [])
      setShowFile(true)
    } catch (e) {
      console.error('Failed to load latest NRD file', e)
    }
  }

  const handleSearch = async () => {
    if (!brandName.trim()) return
    setIsSearching(true)
    try {
      const res = await fetch(getApiUrl(API_ENDPOINTS.BRAND_SEARCH), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ brand: brandName }),
      })

      if (!res.ok) throw new Error('search failed')
      const data = await res.json()
      setResults(data.results || [])
    } catch (e) {
      console.error('Brand search failed', e)
      setResults([])
    } finally {
      setIsSearching(false)
    }
  }

  return (
    <div className="bg-card rounded-xl border border-border shadow-sm hover:shadow-md transition-shadow">
      <div className="p-6 border-b border-border flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Brand Search</h2>
          <p className="text-sm text-muted-foreground mt-2">Show latest NRD file and search for brand-related domains</p>
        </div>
        <button
          onClick={handleShowFile}
          className="bg-muted hover:bg-muted/90 text-muted-foreground px-3 py-1 rounded-md text-sm"
        >
          Show File
        </button>
      </div>

      <div className="p-6 space-y-4">
        {showFile && (
          <div>
            <div className="text-xs text-muted-foreground mb-2">{filename}</div>
            <div className="w-full h-48 overflow-auto bg-muted rounded-lg border border-border p-3 font-mono text-sm text-foreground">
              {domains.length === 0 ? (
                <div className="text-muted-foreground">No domains found in latest file.</div>
              ) : (
                domains.map((d, i) => <div key={i}>{d}</div>)
              )}
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <input
            type="text"
            value={brandName}
            onChange={(e) => setBrandName(e.target.value)}
            placeholder="Enter brand name…"
            className="flex-1 bg-input border border-border rounded-lg px-3 py-2 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
          />
          <button
            onClick={handleSearch}
            disabled={isSearching}
            className="bg-accent hover:bg-accent/90 disabled:bg-accent/50 text-accent-foreground font-medium px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
          >
            <Search className={`w-4 h-4 ${isSearching ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Search</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-2 font-semibold text-foreground">Domain</th>
                <th className="text-center py-3 px-2 font-semibold text-foreground">Fuzzy Match</th>
                <th className="text-center py-3 px-2 font-semibold text-foreground">Regex Hit</th>
                <th className="text-center py-3 px-2"></th>
              </tr>
            </thead>
            <tbody>
              {results.map((result, idx) => (
                <tr key={idx} className="border-b border-border hover:bg-muted/50 transition-colors">
                  <td className="py-3 px-2 font-mono text-foreground">{result.domain}</td>
                  <td className="text-center py-3 px-2 text-foreground">{result.fuzzyScore}%</td>
                  <td className="text-center py-3 px-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      result.regexHit ? 'bg-green-100 text-green-700' : 'bg-muted text-muted-foreground'
                    }`}>
                      {result.regexHit ? 'Yes' : 'No'}
                    </span>
                  </td>
                  <td className="text-center py-3 px-2">
                    {onViewWhois && (
                      <button
                        onClick={() => onViewWhois(result.domain)}
                        className="p-1.5 hover:bg-border rounded transition-colors"
                        title="View WHOIS details"
                      >
                        <Eye className="w-4 h-4 text-accent" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

