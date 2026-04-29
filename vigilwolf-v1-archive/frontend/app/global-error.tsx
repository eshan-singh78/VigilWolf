'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <html>
      <body className="min-h-screen bg-background flex items-center justify-center p-4">
        <div className="bg-card rounded-xl border border-border shadow-lg max-w-md w-full p-6 space-y-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-red-500" />
            <div>
              <h2 className="text-lg font-semibold text-foreground">Critical Error</h2>
              <p className="text-sm text-muted-foreground">
                The application encountered a critical error. Please refresh the page.
              </p>
            </div>
          </div>

          <button
            onClick={() => reset()}
            className="w-full bg-accent hover:bg-accent/90 text-accent-foreground font-medium py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh Page
          </button>
        </div>
      </body>
    </html>
  )
}
