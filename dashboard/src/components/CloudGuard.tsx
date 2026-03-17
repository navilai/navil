import type { ReactNode } from 'react'
import Icon from './Icon'
import PageHeader from './PageHeader'

const hasCloudApi = !!import.meta.env.VITE_API_BASE_URL

interface CloudGuardProps {
  children: ReactNode
  title: string
  subtitle: string
}

/**
 * Wraps cloud-only pages. When VITE_API_BASE_URL is not set (local mode),
 * renders a friendly message instead of the page content.
 */
export default function CloudGuard({ children, title, subtitle }: CloudGuardProps) {
  if (hasCloudApi) return <>{children}</>

  return (
    <div className="space-y-6">
      <PageHeader title={title} subtitle={subtitle} />
      <div className="max-w-lg mx-auto mt-8 text-center animate-fadeIn">
        <div className="glass-card p-8">
          <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-[#00e5c8]/10 border border-[#00e5c8]/20 flex items-center justify-center">
            <Icon name="globe" size={24} className="text-[#00e5c8]" />
          </div>
          <h2 className="text-lg font-bold text-[#f0f4fc] mb-2">Cloud Feature</h2>
          <p className="text-sm text-[#8b9bc0] mb-6 leading-relaxed">
            This feature requires a Navil Cloud connection.
            Connect your local instance to Navil Cloud to unlock analytics,
            billing, webhooks, and custom threat rules.
          </p>
          <a
            href="https://navil.ai"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] transition-all duration-200 hover:-translate-y-0.5"
          >
            <Icon name="external-link" size={14} />
            Get started at navil.ai
          </a>
        </div>
      </div>
    </div>
  )
}
