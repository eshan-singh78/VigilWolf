'use client'

import { X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getApiUrl } from '../lib/api'

interface WhoisModalProps {
  domain: string
  onClose: () => void
}

export default function WhoisModal({ domain, onClose }: WhoisModalProps) {
  const [whois, setWhois] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    setLoading(true)
    setWhois(null)
    fetch(getApiUrl(`/whois?domain=${encodeURIComponent(domain)}`))
      .then(res => res.json())
      .then(data => {
        setWhois(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [domain])

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-xl border border-border shadow-lg max-w-2xl w-full max-h-96 overflow-auto">
        <div className="flex items-center justify-between p-6 border-b border-border sticky top-0 bg-card">
          <h2 className="text-lg font-semibold text-foreground">WHOIS Information - {domain}</h2>
          <button onClick={onClose} className="p-1 hover:bg-border rounded transition-colors">
            <X className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <div className="p-6 space-y-6">
          {loading ? (
            <div className="text-center text-muted-foreground text-lg">fetching...</div>
          ) : whois && !whois.error ? (
            <>
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-3">Summary</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Status</p>
                    <p className="text-foreground font-mono">{Array.isArray(whois.status) ? whois.status.join(', ') : whois.status || '-'}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Created</p>
                    <p className="text-foreground font-mono">{whois.creation_date ? String(whois.creation_date) : '-'}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Expires</p>
                    <p className="text-foreground font-mono">{whois.expiration_date ? String(whois.expiration_date) : '-'}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Updated</p>
                    <p className="text-foreground font-mono">{whois.updated_date ? String(whois.updated_date) : '-'}</p>
                  </div>
                </div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-3">DNS Information</h3>
                <div className="space-y-2 text-sm font-mono text-foreground bg-muted p-3 rounded-lg">
                  {whois.name_servers && Array.isArray(whois.name_servers)
                    ? whois.name_servers.map((ns: string, i: number) => <p key={i}>{ns}</p>)
                    : <p>-</p>}
                </div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-3">Registrant Information</h3>
                <div className="space-y-2 text-sm">
                  <p className="text-muted-foreground">Registrar: <span className="text-foreground font-mono">{whois.registrar || '-'}</span></p>
                  <p className="text-muted-foreground">Country: <span className="text-foreground font-mono">{whois.country || '-'}</span></p>
                  <p className="text-muted-foreground">Emails: <span className="text-foreground font-mono">{whois.emails ? (Array.isArray(whois.emails) ? whois.emails.join(', ') : whois.emails) : '-'}</span></p>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center text-destructive text-lg">{whois?.error || 'No WHOIS info found.'}</div>
          )}
        </div>
      </div>
    </div>
  )
}
