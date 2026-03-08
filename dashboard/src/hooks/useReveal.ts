import { useEffect, useRef } from 'react'

/**
 * Intersection Observer hook that adds a `revealed` class
 * when the element scrolls into view. Works with the `.reveal`
 * and `.reveal-stagger` CSS classes defined in index.css.
 */
export default function useReveal<T extends HTMLElement = HTMLDivElement>(
  threshold = 0.15,
) {
  const ref = useRef<T>(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          el.classList.add('revealed')
          observer.unobserve(el)
        }
      },
      { threshold },
    )

    observer.observe(el)
    return () => observer.disconnect()
  }, [threshold])

  return ref
}
