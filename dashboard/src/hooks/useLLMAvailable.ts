import { useEffect, useState } from 'react'
import { api } from '../api'

interface UseLLMAvailableResult {
  canUseLLM: boolean
  loading: boolean
}

/**
 * Returns canUseLLM=true when the user has configured an LLM API key
 * in Settings. Uses GET /api/local/settings/llm → LLMConfig.api_key_set.
 * No billing, no plan tiers — OSS only.
 */
export default function useLLMAvailable(): UseLLMAvailableResult {
  const [canUseLLM, setCanUseLLM] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getLLMSettings()
      .then(s => setCanUseLLM(s.api_key_set))
      .catch(() => setCanUseLLM(false))
      .finally(() => setLoading(false))
  }, [])

  return { canUseLLM, loading }
}
