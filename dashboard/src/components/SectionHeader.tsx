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
        <p className="uppercase tracking-[0.15em] text-xs font-semibold text-[#00e5c8] mb-3">{eyebrow}</p>
      )}
      <h2 className="text-3xl font-extrabold text-[#f0f4fc]">{title}</h2>
      {subtitle && (
        <p className="text-[#8b9bc0] mt-3 max-w-2xl mx-auto leading-relaxed">{subtitle}</p>
      )}
    </div>
  )
}
