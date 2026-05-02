interface SectionHeaderProps {
  eyebrow?: string
  title: string
  subtitle?: string
  centered?: boolean
}

export default function SectionHeader({
  eyebrow,
  title,
  subtitle,
  centered = true,
}: SectionHeaderProps) {
  return (
    <div className={centered ? 'text-center' : ''}>
      {eyebrow && (
        <p className="uppercase tracking-[0.15em] text-xs font-semibold text-signal-cyan mb-3">{eyebrow}</p>
      )}
      <h2 className="text-3xl font-extrabold text-ink">{title}</h2>
      {subtitle && (
        <p className="text-ink-secondary mt-3 max-w-2xl mx-auto leading-relaxed">{subtitle}</p>
      )}
    </div>
  )
}
