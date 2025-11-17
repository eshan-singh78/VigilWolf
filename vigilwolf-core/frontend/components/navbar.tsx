'use client'

import { Shield } from 'lucide-react'

interface NavbarProps {
  activeTab: 'home' | 'monitoring'
  setActiveTab: (tab: 'home' | 'monitoring') => void
}

export default function Navbar({ activeTab, setActiveTab }: NavbarProps) {
  return (
    <nav className="fixed top-0 left-0 right-0 bg-card border-b border-border shadow-sm z-50">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-accent rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-accent-foreground" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-foreground">VigilWolf</h1>
            <p className="text-xs text-muted-foreground">Security Monitoring</p>
          </div>
        </div>

        {/* Navigation Links */}
        <div className="flex items-center gap-8">
          <button
            onClick={() => setActiveTab('home')}
            className={`text-sm font-medium transition-colors ${
              activeTab === 'home'
                ? 'text-accent border-b-2 border-accent pb-1'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Home
          </button>
          <button
            onClick={() => setActiveTab('monitoring')}
            className={`text-sm font-medium transition-colors ${
              activeTab === 'monitoring'
                ? 'text-accent border-b-2 border-accent pb-1'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Monitoring
          </button>
          <a href="#" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
            Settings
          </a>
        </div>
      </div>
    </nav>
  )
}
