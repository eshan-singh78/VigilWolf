'use client'

import { X } from 'lucide-react'

interface WhoisModalProps {
  domain: string
  onClose: () => void
}

export default function WhoisModal({ domain, onClose }: WhoisModalProps) {
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
          {/* Summary Tab */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Summary</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-muted-foreground">Status</p>
                <p className="text-foreground font-mono">active</p>
              </div>
              <div>
                <p className="text-muted-foreground">Created</p>
                <p className="text-foreground font-mono">2021-05-15</p>
              </div>
              <div>
                <p className="text-muted-foreground">Expires</p>
                <p className="text-foreground font-mono">2026-05-15</p>
              </div>
              <div>
                <p className="text-muted-foreground">Updated</p>
                <p className="text-foreground font-mono">2024-02-20</p>
              </div>
            </div>
          </div>

          {/* DNS Info */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">DNS Information</h3>
            <div className="space-y-2 text-sm font-mono text-foreground bg-muted p-3 rounded-lg">
              <p>ns1.example.com</p>
              <p>ns2.example.com</p>
              <p>ns3.example.com</p>
            </div>
          </div>

          {/* Registration */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Registrant Information</h3>
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">Organization: <span className="text-foreground font-mono">Example Corp</span></p>
              <p className="text-muted-foreground">Country: <span className="text-foreground font-mono">US</span></p>
              <p className="text-muted-foreground">Email: <span className="text-foreground font-mono">admin@example.com</span></p>
            </div>
          </div>

          {/* VirusTotal */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">VirusTotal Data</h3>
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">Detections: <span className="text-green-600 font-mono">0/91</span></p>
              <p className="text-muted-foreground">Last Analysis: <span className="text-foreground font-mono">2024-11-16</span></p>
              <p className="text-muted-foreground">Reputation: <span className="text-green-600 font-mono">Clean</span></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
