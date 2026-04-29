'use client'

import { Shield } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

export default function Navbar() {
  const pathname = usePathname()
  
  const isHome = pathname === '/'
  const isMonitor = pathname === '/monitor'
  const isSettings = pathname === '/settings'
  
  return (
    <nav className="fixed top-0 left-0 right-0 bg-card border-b border-border shadow-sm z-50">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="w-10 h-10 bg-accent rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-accent-foreground" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-foreground">VigilWolf</h1>
            <p className="text-xs text-muted-foreground">Security Monitoring</p>
          </div>
        </Link>

        {/* Navigation Links */}
        <div className="flex items-center gap-8">
          <Link
            href="/"
            className={`text-sm font-medium transition-colors ${
              isHome
                ? 'text-accent border-b-2 border-accent pb-1'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Home
          </Link>
          <Link
            href="/monitor"
            className={`text-sm font-medium transition-colors ${
              isMonitor
                ? 'text-accent border-b-2 border-accent pb-1'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Monitoring
          </Link>
          <Link
            href="/settings"
            className={`text-sm font-medium transition-colors ${
              isSettings
                ? 'text-accent border-b-2 border-accent pb-1'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Settings
          </Link>
        </div>
      </div>
    </nav>
  )
}
