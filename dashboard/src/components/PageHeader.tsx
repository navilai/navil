interface PageHeaderProps {
  title: string
  subtitle?: string
  children?: React.ReactNode
}

export default function PageHeader({ title, subtitle, children }: PageHeaderProps) {
  return (
    <header className="flex items-center justify-between pb-6 mb-6 border-b border-[#2a3650]">
      <div>
        <h2 className="text-2xl font-extrabold tracking-tight text-[#f0f4fc]">{title}</h2>
        {subtitle && <p className="text-sm text-[#8b9bc0] mt-1">{subtitle}</p>}
      </div>
      {children}
    </header>
  )
}
