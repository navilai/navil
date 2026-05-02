interface PageHeaderProps {
  title: string
  subtitle?: string
  children?: React.ReactNode
}

export default function PageHeader({ title, subtitle, children }: PageHeaderProps) {
  return (
    <header className="flex items-center justify-between pb-6 mb-6 border-b border-rule">
      <div>
        <h2 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h2>
        {subtitle && <p className="text-sm text-ink-secondary mt-1">{subtitle}</p>}
      </div>
      {children}
    </header>
  )
}
