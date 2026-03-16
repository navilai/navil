import { useCallback } from 'react'
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

/**
 * React hook that wraps cloudApi with Clerk auth tokens.
 * Use this in components instead of calling cloudApi directly
 * to ensure every request includes a valid Bearer token.
 */
export default function useCloudApi() {
  const { getToken } = useAuth()

  const withToken = useCallback(async () => {
    const token = await getToken()
    return token
  }, [getToken])

  return {
    // Org profile
    getOrgProfile: useCallback(async (): Promise<OrgProfile> => {
      const token = await withToken()
      return cloudApi.getOrgProfile(token)
    }, [withToken]),

    // Billing
    createCheckout: useCallback(async (tier: string, interval: 'monthly' | 'annual' = 'monthly'): Promise<CheckoutResponse> => {
      const token = await withToken()
      return cloudApi.createCheckout(tier, interval, token)
    }, [withToken]),

    createPortal: useCallback(async (): Promise<PortalResponse> => {
      const token = await withToken()
      return cloudApi.createPortal(token)
    }, [withToken]),

    // Webhooks
    listWebhooks: useCallback(async (): Promise<WebhookEndpoint[]> => {
      const token = await withToken()
      return cloudApi.listWebhooks(token)
    }, [withToken]),

    createWebhook: useCallback(async (data: CreateWebhookRequest): Promise<CreateWebhookResponse> => {
      const token = await withToken()
      return cloudApi.createWebhook(data, token)
    }, [withToken]),

    updateWebhook: useCallback(async (id: string, data: UpdateWebhookRequest): Promise<WebhookEndpoint> => {
      const token = await withToken()
      return cloudApi.updateWebhook(id, data, token)
    }, [withToken]),

    deleteWebhook: useCallback(async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.deleteWebhook(id, token)
    }, [withToken]),

    testWebhook: useCallback(async (id: string): Promise<TestDeliveryResponse> => {
      const token = await withToken()
      return cloudApi.testWebhook(id, token)
    }, [withToken]),

    listDeliveries: useCallback(async (webhookId: string): Promise<WebhookDelivery[]> => {
      const token = await withToken()
      return cloudApi.listDeliveries(webhookId, token)
    }, [withToken]),

    // Analytics
    getTimeseries: useCallback(async (days = 7): Promise<TimeseriesResponse> => {
      const token = await withToken()
      return cloudApi.getTimeseries(days, token)
    }, [withToken]),

    getTopThreats: useCallback(async (days = 7): Promise<TopThreatsResponse> => {
      const token = await withToken()
      return cloudApi.getTopThreats(days, token)
    }, [withToken]),

    // Threat rules
    listThreatRules: useCallback(async (): Promise<ThreatRule[]> => {
      const token = await withToken()
      return cloudApi.listThreatRules(token)
    }, [withToken]),

    createThreatRule: useCallback(async (data: CreateThreatRuleRequest): Promise<ThreatRule> => {
      const token = await withToken()
      return cloudApi.createThreatRule(data, token)
    }, [withToken]),

    updateThreatRule: useCallback(async (id: string, data: Partial<ThreatRule>): Promise<ThreatRule> => {
      const token = await withToken()
      return cloudApi.updateThreatRule(id, data, token)
    }, [withToken]),

    deleteThreatRule: useCallback(async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.deleteThreatRule(id, token)
    }, [withToken]),

    testThreatRule: useCallback(async (pattern: string, sample: string): Promise<TestRuleResult> => {
      const token = await withToken()
      return cloudApi.testThreatRule(pattern, sample, token)
    }, [withToken]),

    // API Keys
    listApiKeys: useCallback(async (): Promise<ApiKey[]> => {
      const token = await withToken()
      return cloudApi.listApiKeys(token)
    }, [withToken]),

    createApiKey: useCallback(async (label: string): Promise<CreateApiKeyResponse> => {
      const token = await withToken()
      return cloudApi.createApiKey(label, token)
    }, [withToken]),

    revokeApiKey: useCallback(async (id: string): Promise<void> => {
      const token = await withToken()
      return cloudApi.revokeApiKey(id, token)
    }, [withToken]),
  }
}
