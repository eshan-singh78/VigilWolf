'use client'

import { ExternalLink, AlertCircle } from 'lucide-react'
import { useRouter } from 'next/navigation'

interface MonitoredDomain {
  id: string
  domain: string
  frequency: string
  baselineStatus: 'Done' | 'Pending'
  lastCheck: string
  changeDetected: boolean
  groupId: string
}

interface MonitoringListTableProps {
  domains: MonitoredDomain[]
}

export default function MonitoringListTable({ domains }: MonitoringListTableProps) {
  const router = useRouter()

  const handleExplore = (domainId: string) => {
    router.push(`/domain/${domainId}`)
  }

  return (
    <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
      <div className="p-6 border-b border-border">
        <h2 className="text-lg font-semibold text-foreground">Monitoring List</h2>
        <p className="text-sm text-muted-foreground mt-2">{domains.length} domains being monitored</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left py-3 px-6 font-semibold text-foreground">Domain</th>
              <th className="text-left py-3 px-6 font-semibold text-foreground">Frequency</th>
              <th className="text-center py-3 px-6 font-semibold text-foreground">Baseline</th>
              <th className="text-left py-3 px-6 font-semibold text-foreground">Last Check</th>
              <th className="text-center py-3 px-6 font-semibold text-foreground">Changes</th>
              <th className="text-center py-3 px-6 font-semibold text-foreground">Action</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((domain) => (
              <tr key={domain.id} className="border-b border-border hover:bg-muted/50 transition-colors">
                <td className="py-4 px-6">
                  <code className="text-foreground font-mono">{domain.domain}</code>
                </td>
                <td className="py-4 px-6 text-muted-foreground">{domain.frequency}</td>
                <td className="py-4 px-6 text-center">
                  <span className={`px-2.5 py-1 rounded text-xs font-medium ${
                    domain.baselineStatus === 'Done'
                      ? 'bg-green-100 text-green-700'
                      : 'bg-yellow-100 text-yellow-700'
                  }`}>
                    {domain.baselineStatus}
                  </span>
                </td>
                <td className="py-4 px-6 text-muted-foreground text-sm">{domain.lastCheck}</td>
                <td className="py-4 px-6 text-center">
                  {domain.changeDetected ? (
                    <span className="flex items-center justify-center gap-1 px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-medium w-fit mx-auto">
                      <AlertCircle className="w-3 h-3" />
                      Yes
                    </span>
                  ) : (
                    <span className="text-muted-foreground text-xs">No</span>
                  )}
                </td>
                <td className="py-4 px-6 text-center">
                  <button
                    onClick={() => handleExplore(domain.id)}
                    className="p-1.5 hover:bg-border rounded transition-colors inline-flex items-center gap-1 text-accent text-xs font-medium"
                  >
                    <ExternalLink className="w-4 h-4" />
                    <span className="hidden sm:inline">Explore</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
