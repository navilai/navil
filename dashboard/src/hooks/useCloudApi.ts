import { useCallback, useMemo } from 'react'
import { useAuth } from '@clerk/clerk-react'
import {
  cloudApi,
  type OrgProfile,
  type CheckoutResponse,
  type PortalResponse,
  type WebhookEndpoint,
  type CreateWebhookRequest,
  type CreateWebhookResponse,
  type UpdateWebhookRequest,
  type WebhookDelivery,
  type TestDeliveryResponse,
  type TimeseriesResponse,
  type TopThreatsResponse,
  type ThreatRule,
  type CreateThreatRuleRequest,
  type TestRuleResult,
  type ApiKey,
  type CreateApiKeyResponse,
} from '../cloudApi'

const hasClerk = !!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

/**
 * Stub that mirrors useAuth() shape but returns nulls.
 * Used when running locally without ClerkProvider.
 */
function useNoAuth() {
  return { getToken: async () => null as string | null }
}

/**
 * React hook that wraps cloudApi with Clerk auth tokens.
 * Use this in components instead of calling cloudApi directly
 * to ensure every request includes a valid Bearer token.
 *
 * In local mode (no Clerk key), returns a stub that passes null tokens.
 * Cloud API calls will fail gracefully; pages should check isCloudMode.
 *
 * Returns a stable object (via useMemo) to avoid infinite
 * re-render loops when used as a useEffect/useCallback dependency.
 */
export default function useCloudApi() {
  // hasClerk is a build-time constant — this conditional never changes
  // at runtime, so the hook call order is stable across renders.
  // eslint-disable-next-line react-hooks/rules-of-hooks
  const { getToken } = hasClerk ? useAuth() : useNoAuth()

  const withToken = useCallback(async () => {
    const token = await getToken()
    return token
  }, [getToken])

  return useMemo(() => ({
    // Org profile
    getOrgProfile: async (): Promise<OrgProfile> => {
      const token = await withToken()
      return cloudApi.getOrgProfile(token)
    },

    // Billing
    createCheckout: async (tier: string, interval: 'monthly' | 'annual' = 'monthly'): Promise<CheckoutResponse> => {
      const token = await withToken()
      return cloudApi.createCheckout(tier, interval, token)
    },

    createPortal: async (): Promise<PortalResponse> => {
      const token = await withToken()
      return cloudApi.createPortal(token)
    },

    // Webhooks
    listWebhooks: async (): Promise<WebhookEndpoint[]> => {
      const token = await withToken()
      return cloudApi.listWebhooks(token)
    },

    createWebhook: async (data: CreateWebhookRequest): Promise<CreateWebhookResponse> => {
      const token = await withToken()
      return cloudApi.createWebhook(data, token)
    },

    updateWebhook: async (id: string, data: UpdateWebhookRequest): Promise<WebhookEndpoint> => {
      const token = await withToken()
      return cloudApi.updateWebhook(id, data, token)
    },

    deleteWebhook: async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.deleteWebhook(id, token)
    },

    testWebhook: async (id: string): Promise<TestDeliveryResponse> => {
      const token = await withToken()
      return cloudApi.testWebhook(id, token)
    },

    listDeliveries: async (webhookId: string): Promise<WebhookDelivery[]> => {
      const token = await withToken()
      return cloudApi.listDeliveries(webhookId, token)
    },

    // Analytics
    getTimeseries: async (days = 7): Promise<TimeseriesResponse> => {
      const token = await withToken()
      return cloudApi.getTimeseries(days, token)
    },

    getTopThreats: async (days = 7): Promise<TopThreatsResponse> => {
      const token = await withToken()
      return cloudApi.getTopThreats(days, token)
    },

    // Threat rules
    listThreatRules: async (): Promise<ThreatRule[]> => {
      const token = await withToken()
      return cloudApi.listThreatRules(token)
    },

    createThreatRule: async (data: CreateThreatRuleRequest): Promise<ThreatRule> => {
      const token = await withToken()
      return cloudApi.createThreatRule(data, token)
    },

    updateThreatRule: async (id: string, data: Partial<ThreatRule>): Promise<ThreatRule> => {
      const token = await withToken()
      return cloudApi.updateThreatRule(id, data, token)
    },

    deleteThreatRule: async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.deleteThreatRule(id, token)
    },

    testThreatRule: async (pattern: string, sample: string): Promise<TestRuleResult> => {
      const token = await withToken()
      return cloudApi.testThreatRule(pattern, sample, token)
    },

    // API Keys
    listApiKeys: async (): Promise<ApiKey[]> => {
      const token = await withToken()
      return cloudApi.listApiKeys(token)
    },

    createApiKey: async (label: string): Promise<CreateApiKeyResponse> => {
      const token = await withToken()
      return cloudApi.createApiKey(label, token)
    },

    revokeApiKey: async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.revokeApiKey(id, token)
    },
  }), [withToken])
}
