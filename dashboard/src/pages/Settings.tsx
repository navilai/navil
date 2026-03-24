import { useEffect, useState, useCallback } from 'react'
import { api, LLMConfig, MachineInfo } from '../api'
import { type ApiKey } from '../cloudApi'
import useCloudApi from '../hooks/useCloudApi'
import PageHeader from '../components/PageHeader'
import Icon from '../components/Icon'
import useSessionState from '../hooks/useSessionState'

const providers = [
  { value: 'anthropic', label: 'Anthropic (Claude)', hint: 'ANTHROPIC_API_KEY' },
  { value: 'openai', label: 'OpenAI', hint: 'OPENAI_API_KEY' },
  { value: 'gemini', label: 'Google Gemini', hint: 'GEMINI_API_KEY' },
  { value: 'ollama', label: 'Ollama (Local)', hint: 'No API key needed — runs locally at localhost:11434' },
  { value: 'openai_compatible', label: 'OpenAI Compatible', hint: 'Any OpenAI-compatible API' },
]

const compatibleExamples = [
  { name: 'OpenRouter', url: 'https://openrouter.ai/api/v1' },
  { name: 'Together AI', url: 'https://api.together.xyz/v1' },
  { name: 'Groq', url: 'https://api.groq.com/openai/v1' },
  { name: 'DeepSeek', url: 'https://api.deepseek.com/v1' },
  { name: 'Fireworks', url: 'https://api.fireworks.ai/inference/v1' },
  { name: 'Ollama', url: 'http://localhost:11434/v1' },
]

// Cloud mode = deployed on Vercel with a cloud API URL configured.
// Local-only features (LLM config, telemetry toggle) require `navil cloud serve` running locally.
const isCloudMode = !!import.meta.env.VITE_API_BASE_URL

export default function Settings() {
  const [config, setConfig] = useState<LLMConfig | null>(null)
  const [provider, setProvider] = useState('anthropic')
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [model, setModel] = useState('')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [saveResult, setSaveResult] = useSessionState<{ ok: boolean; msg: string } | null>('settings_save', null)
  const [testResult, setTestResult] = useSessionState<{ ok: boolean; msg: string } | null>('settings_test', null)

  const [machineInfo, setMachineInfo] = useState<MachineInfo | null>(null)

  const isOllama = provider === 'ollama'
  const isCompatible = provider === 'openai_compatible'

  useEffect(() => {
    if (isCloudMode) return
    api.getMachineInfo().then(setMachineInfo).catch(() => {})
  }, [])

  useEffect(() => {
    if (isCloudMode) return // Skip local API calls in cloud mode
    api.getLLMSettings().then(c => {
      setConfig(c)
      if (c.provider) {
        if (c.provider === 'openai' && c.base_url?.includes('11434')) setProvider('ollama')
        else if (c.provider === 'openai' && c.base_url) setProvider('openai_compatible')
        else setProvider(c.provider)
      }
      if (c.base_url) setBaseUrl(c.base_url)
    }).catch(() => {})
  }, [])

  const handleSave = async () => {
    if (!apiKey.trim() && !isCompatible && !isOllama) return
    if (isCompatible && !baseUrl.trim()) return
    setSaving(true)
    setSaveResult(null)
    setTestResult(null)
    try {
      const res = await api.updateLLMSettings(provider, apiKey.trim(), baseUrl.trim(), model.trim())
      setConfig(res)
      setApiKey('')
      setSaveResult({ ok: true, msg: 'LLM configuration saved successfully.' })
    } catch (e: unknown) {
      setSaveResult({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await api.testLLMConnection(provider, apiKey.trim(), baseUrl.trim(), model.trim())
      setTestResult(res.success
        ? { ok: true, msg: 'Connection successful!' }
        : { ok: false, msg: res.error || 'Connection failed.' }
      )
    } catch (e: unknown) {
      setTestResult({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setTesting(false)
    }
  }

  const selectedHint = providers.find(p => p.value === provider)?.hint
  const canSave = isOllama
    ? (model.trim() || true)
    : isCompatible
      ? baseUrl.trim() && (apiKey.trim() || config?.api_key_set)
      : apiKey.trim()

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Configure Navil preferences" />

      {/* LLM Configuration */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
          <Icon name="sparkles" size={16} className="text-violet-400" />
          LLM Configuration
        </h3>

        {isCloudMode ? (
          <div className="p-4 rounded-[12px] border bg-[#1a2235] border-[#2a3650]">
            <p className="text-sm text-[#8b9bc0] mb-2">
              LLM configuration is managed locally on each machine running Navil.
            </p>
            <div className="p-3 rounded-lg bg-[#111827] border border-[#2a3650]">
              <code className="text-xs font-mono text-[#00e5c8] block leading-relaxed">
                <span className="text-[#5a6a8a]"># Configure LLM provider locally:</span>{'\n'}
                navil cloud serve{'\n'}
                <span className="text-[#5a6a8a]"># Then open</span> http://localhost:5173/settings
              </code>
            </div>
            <p className="text-[10px] text-[#5a6a8a] mt-2 flex items-center gap-1">
              <Icon name="info" size={10} />
              Supports Anthropic, OpenAI, Gemini, Ollama, and OpenAI-compatible APIs
            </p>
          </div>
        ) : (
          <>
            {/* Connection status */}
            {config && (
              <div className={`mb-5 p-3 rounded-[12px] border flex items-center gap-3 ${
                config.api_key_set
                  ? 'bg-[#34d399]/5 border-[#34d399]/20'
                  : 'bg-[#fbbf24]/5 border-[#fbbf24]/20'
              }`}>
                <div className={`w-2 h-2 rounded-full ${config.api_key_set ? 'bg-[#34d399]' : 'bg-[#fbbf24]'}`} />
                <div>
                  <p className={`text-sm ${config.api_key_set ? 'text-[#34d399]' : 'text-[#fbbf24]'}`}>
                    {config.api_key_set ? 'Connected' : 'Not configured'}
                  </p>
                  {config.api_key_set && (
                    <p className="text-xs text-[#5a6a8a]">
                      Provider: {config.provider} · Model: {config.model}
                      {config.base_url ? ` · ${config.base_url}` : ''}
                    </p>
                  )}
                </div>
              </div>
            )}

            {config && !config.available && (
              <div className="mb-5 p-3 rounded-[12px] border bg-[#ff4d6a]/5 border-[#ff4d6a]/20 flex items-center gap-3">
                <Icon name="warning" size={14} className="text-[#ff4d6a] shrink-0" />
                <div>
                  <p className="text-sm text-[#ff4d6a]">LLM SDKs not installed</p>
                  <p className="text-xs text-[#5a6a8a]">
                    Install with: <code className="font-mono text-[#ff4d6a]/80">pip install navil[llm]</code>
                  </p>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {/* Provider */}
              <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Provider</label>
                <select
                  value={provider}
                  onChange={e => { setProvider(e.target.value); setSaveResult(null); setTestResult(null) }}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
                >
                  {providers.map(p => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
                <p className="text-xs text-[#5a6a8a] mt-1">
                  {isOllama
                    ? 'Runs locally — no API key needed. Make sure Ollama is running on your machine.'
                    : isCompatible
                      ? 'Works with OpenRouter, Together AI, Groq, DeepSeek, Fireworks, and any OpenAI-compatible API'
                      : <>Or set via environment variable: <code className="font-mono text-[#5a6a8a]">{selectedHint}</code></>
                  }
                </p>
              </div>

              {/* Base URL — only for OpenAI Compatible */}
              {isCompatible && (
                <div>
                  <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Base URL</label>
                  <input
                    value={baseUrl}
                    onChange={e => { setBaseUrl(e.target.value); setSaveResult(null) }}
                    className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
                    placeholder="https://api.example.com/v1"

                  />
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {compatibleExamples.map(ex => (
                      <button
                        key={ex.name}
                        onClick={() => { setBaseUrl(ex.url); setSaveResult(null) }}
                        className="px-2 py-0.5 text-[10px] bg-[#111827] text-[#8b9bc0] border border-[#2a3650] rounded hover:border-[#5a6a8a] hover:text-[#f0f4fc] transition-colors"
                      >
                        {ex.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Model override */}
              {(isCompatible || isOllama) && (
                <div>
                  <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Model {!isOllama && <span className="text-[#5a6a8a]">(optional)</span>}</label>
                  <input
                    value={model}
                    onChange={e => { setModel(e.target.value); setSaveResult(null) }}
                    className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
                    placeholder={isOllama ? 'e.g., llama3.2, deepseek-r1:70b, qwen3' : 'e.g., anthropic/claude-sonnet-4, deepseek-chat, llama-3.1-70b'}

                  />
                </div>
              )}

              {/* API Key — hidden for Ollama */}
              {!isOllama && <div>
                <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={e => { setApiKey(e.target.value); setSaveResult(null) }}
                  onKeyDown={e => e.key === 'Enter' && handleSave()}
                  className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none font-mono transition-colors"
                  placeholder={config?.api_key_set ? '--------  (key is set — enter new to replace)' : 'Paste your API key here'}

                />
                <p className="text-xs text-[#5a6a8a] mt-1 flex items-center gap-1">
                  <Icon name="lock" size={10} className="text-[#5a6a8a]" />
                  Stored in memory only. Not persisted to disk.
                </p>
              </div>}

              {/* Buttons */}
              <div className="flex gap-3 pt-1">
                <button
                  onClick={handleSave}
                  disabled={!canSave || saving}
                  className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
                >
                  <Icon name="check" size={14} />
                  {saving ? 'Saving...' : 'Save'}
                </button>
                <button
                  onClick={handleTest}
                  disabled={testing || (!config?.api_key_set && !isOllama && !apiKey.trim())}
                  className="px-4 py-2.5 bg-[#1a2235] text-[#f0f4fc] border border-[#2a3650] rounded-lg text-sm font-medium hover:bg-[#1f2a40] hover:border-[#5a6a8a] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
                >
                  <Icon name="activity" size={14} className={testing ? 'animate-spin' : ''} />
                  {testing ? 'Testing...' : 'Test Connection'}
                </button>
              </div>

              {/* Result messages */}
              {saveResult && (
                <div className={`p-3 rounded-[12px] border animate-fadeIn ${
                  saveResult.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
                }`}>
                  <p className={`text-sm flex items-center gap-2 ${saveResult.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
                    <Icon name={saveResult.ok ? 'check' : 'warning'} size={14} />
                    {saveResult.msg}
                  </p>
                </div>
              )}
              {testResult && (
                <div className={`p-3 rounded-[12px] border animate-fadeIn ${
                  testResult.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
                }`}>
                  <p className={`text-sm flex items-center gap-2 ${testResult.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
                    <Icon name={testResult.ok ? 'check' : 'warning'} size={14} className="shrink-0" />
                    <span className="line-clamp-2 break-words">{testResult.msg}</span>
                  </p>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* API Key Management */}
      <ApiKeyManager />

      {/* Community Threat Feed */}
      <TelemetryToggle />

      {/* About */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="info" size={16} className="text-[#8b9bc0]" />
          About
        </h3>
        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-[#5a6a8a]">Version</span>
            <span className="text-[#f0f4fc] font-mono">{import.meta.env.VITE_APP_VERSION || '0.1.0'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#5a6a8a]">LLM SDK</span>
            <span className={`font-mono ${isCloudMode ? 'text-[#5a6a8a]' : config?.available ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
              {isCloudMode ? 'Local only' : config?.available ? 'Installed' : 'Not installed'}
            </span>
          </div>
          {config?.api_key_set && (
            <>
              <div className="flex justify-between">
                <span className="text-[#5a6a8a]">Active Provider</span>
                <span className="text-[#f0f4fc] font-mono">{config.provider}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#5a6a8a]">Active Model</span>
                <span className="text-[#f0f4fc] font-mono">{config.model}</span>
              </div>
              {config.base_url && (
                <div className="flex justify-between">
                  <span className="text-[#5a6a8a]">Base URL</span>
                  <span className="text-[#f0f4fc] font-mono text-xs truncate max-w-[250px]">{config.base_url}</span>
                </div>
              )}
            </>
          )}
          {machineInfo?.machine_id && (
            <div className="flex justify-between">
              <span className="text-[#5a6a8a]">Machine ID</span>
              <span className="text-[#f0f4fc] font-mono text-xs" title={machineInfo.machine_id}>
                {machineInfo.machine_id.length > 12
                  ? `${machineInfo.machine_id.slice(0, 8)}...`
                  : machineInfo.machine_id}
              </span>
            </div>
          )}
          {machineInfo?.machine_label && (
            <div className="flex justify-between">
              <span className="text-[#5a6a8a]">Machine Label</span>
              <span className="text-[#f0f4fc] font-mono">{machineInfo.machine_label}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

const hasClerk = !!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

function ApiKeyManager() {
  const cloud = useCloudApi()
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(!hasClerk ? false : true)
  const [error, setError] = useState('')
  const [label, setLabel] = useState('')
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; msg: string } | null>(null)

  const fetchKeys = useCallback(() => {
    if (!hasClerk) return // No cloud auth — skip API call
    setLoading(true)
    setError('')
    cloud.listApiKeys()
      .then(setKeys)
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : 'Failed to load API keys.')
      })
      .finally(() => setLoading(false))
  }, [cloud])

  useEffect(() => { fetchKeys() }, [fetchKeys])

  // Local mode — show link to cloud signup instead of key manager
  if (!hasClerk) {
    return (
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
          <Icon name="key" size={16} className="text-[#fbbf24]" />
          Cloud API Key
        </h3>
        <div className="p-4 rounded-[12px] border bg-[#1a2235] border-[#2a3650] space-y-4">
          <p className="text-sm text-[#8b9bc0]">
            Navil uses a community threat feed — every instance shares anonymized attack data and receives real-time threat intelligence in return. Connect with a free API key to join.
          </p>

          <a
            href="https://navil.ai/settings"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2 w-full px-4 py-3 bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/20 rounded-lg text-sm font-semibold hover:bg-[#00e5c8]/20 hover:-translate-y-0.5 transition-all duration-200"
          >
            <Icon name="external-link" size={14} />
            Get API Key at navil.ai
          </a>

          <div className="p-3 rounded-lg bg-[#111827] border border-[#2a3650]">
            <code className="text-xs font-mono text-[#00e5c8] block leading-relaxed">
              <span className="text-[#5a6a8a]"># Then connect your local instance:</span>{'\n'}
              navil init --api-key navil_live_...
            </code>
          </div>

          <p className="text-[10px] text-[#5a6a8a] flex items-center gap-1">
            <Icon name="info" size={10} />
            Free community tier — no credit card required. Share data, get protection.
          </p>
        </div>
      </div>
    )
  }

  const handleCreate = async () => {
    if (!label.trim()) return
    setCreating(true)
    setActionMsg(null)
    setNewKey(null)
    try {
      const res = await cloud.createApiKey(label.trim())
      setNewKey(res.raw_key)
      setLabel('')
      setCopied(false)
      fetchKeys()
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (id: string) => {
    setRevoking(id)
    setActionMsg(null)
    try {
      await cloud.revokeApiKey(id)
      setActionMsg({ ok: true, msg: 'API key revoked.' })
      setKeys(prev => prev.filter(k => k.id !== id))
    } catch (e: unknown) {
      setActionMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setRevoking(null)
    }
  }

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
      <h3 className="text-sm font-semibold text-[#f0f4fc] mb-5 flex items-center gap-2">
        <Icon name="key" size={16} className="text-[#fbbf24]" />
        API Keys
      </h3>

      {/* Generate new key */}
      <div className="space-y-4">
        <div className="flex gap-3">
          <input
            value={label}
            onChange={e => setLabel(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleCreate()}
            className="flex-1 bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
            placeholder="Key label (e.g., Production, CI/CD)"
          />
          <button
            onClick={handleCreate}
            disabled={!label.trim() || creating}
            className="px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200 shrink-0"
          >
            <Icon name="key" size={14} />
            {creating ? 'Generating...' : 'Generate API Key'}
          </button>
        </div>

        {/* Newly created key */}
        {newKey && (
          <div className="p-3 rounded-[12px] border bg-[#fbbf24]/5 border-[#fbbf24]/20 animate-fadeIn">
            <p className="text-xs text-[#fbbf24] font-medium mb-2 flex items-center gap-1.5">
              <Icon name="warning" size={12} />
              Copy this key now — it will not be shown again
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-[#0d1117] border border-[#2a3650] rounded-lg px-3 py-2 text-sm font-mono text-[#f0f4fc] select-all break-all">
                {newKey}
              </code>
              <button
                onClick={handleCopy}
                className="px-3 py-2 bg-[#1a2235] border border-[#2a3650] rounded-lg text-[#8b9bc0] hover:text-[#f0f4fc] hover:border-[#5a6a8a] transition-all duration-200 shrink-0"
              >
                <Icon name={copied ? 'check' : 'copy'} size={14} className={copied ? 'text-[#34d399]' : ''} />
              </button>
            </div>
          </div>
        )}

        {/* Action messages */}
        {actionMsg && (
          <div className={`p-3 rounded-[12px] border animate-fadeIn ${
            actionMsg.ok ? 'bg-[#34d399]/5 border-[#34d399]/20' : 'bg-[#ff4d6a]/5 border-[#ff4d6a]/20'
          }`}>
            <p className={`text-sm flex items-center gap-2 ${actionMsg.ok ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
              <Icon name={actionMsg.ok ? 'check' : 'warning'} size={14} />
              {actionMsg.msg}
            </p>
          </div>
        )}

        {/* Existing keys list */}
        {loading ? (
          <div className="skeleton h-16 rounded-lg" />
        ) : error ? (
          <div className="p-3 rounded-[12px] border bg-[#ff4d6a]/5 border-[#ff4d6a]/20">
            <p className="text-sm text-[#ff4d6a] flex items-center gap-2">
              <Icon name="warning" size={14} />
              {error}
            </p>
          </div>
        ) : keys.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-sm text-[#8b9bc0]">No API keys yet.</p>
            <p className="text-xs text-[#5a6a8a] mt-0.5">Generate a key to authenticate with the Navil Cloud API.</p>
          </div>
        ) : (
          <div className="bg-[#111827] rounded-lg border border-[#2a3650] overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#2a3650] text-[#5a6a8a]">
                  <th className="text-left px-3 py-2 font-medium">Prefix</th>
                  <th className="text-left px-3 py-2 font-medium">Label</th>
                  <th className="text-left px-3 py-2 font-medium">Created</th>
                  <th className="text-left px-3 py-2 font-medium">Last Used</th>
                  <th className="text-right px-3 py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k.id} className="border-b border-[#2a3650]/50 hover:bg-[#1a2235] transition-colors">
                    <td className="px-3 py-2 font-mono text-[#00e5c8]">{k.key_prefix}...</td>
                    <td className="px-3 py-2 text-[#f0f4fc]">{k.label}</td>
                    <td className="px-3 py-2 text-[#5a6a8a]">
                      {new Date(k.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                    </td>
                    <td className="px-3 py-2 text-[#5a6a8a]">
                      {k.last_used_at
                        ? new Date(k.last_used_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                        : 'Never'}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => handleRevoke(k.id)}
                        disabled={revoking === k.id}
                        className="px-2 py-1 text-[10px] bg-[#ff4d6a]/10 text-[#ff4d6a] border border-[#ff4d6a]/20 rounded hover:bg-[#ff4d6a]/20 disabled:opacity-50 transition-all duration-200"
                      >
                        {revoking === k.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-[10px] text-[#5a6a8a] flex items-center gap-1">
          <Icon name="lock" size={10} className="text-[#5a6a8a]" />
          API keys are hashed and cannot be retrieved after creation. Store them securely.
        </p>
      </div>
    </div>
  )
}

function TelemetryToggle() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [mode, setMode] = useState<'community' | 'paid' | null>(null)
  const [apiKeyPresent, setApiKeyPresent] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (isCloudMode) return // Skip local API calls in cloud mode
    api.getTelemetrySettings()
      .then(r => {
        setEnabled(r.cloud_sync_enabled)
        setMode(r.mode ?? 'community')
        setApiKeyPresent(r.api_key_present ?? false)
      })
      .catch(() => {
        setEnabled(false)
        setMode('community')
      })
  }, [])

  const toggle = async () => {
    if (enabled === null) return
    setSaving(true)
    setError(null)
    try {
      const res = await api.updateTelemetrySettings(!enabled)
      setEnabled(res.cloud_sync_enabled)
      setMode(res.mode ?? mode)
      setApiKeyPresent(res.api_key_present ?? apiKeyPresent)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      if (msg.includes('403') || msg.toLowerCase().includes('forbidden') || msg.toLowerCase().includes('community')) {
        setError('Community mode requires threat feed sync to be enabled. Add a Navil Cloud API key to unlock independent mode.')
      } else {
        setError(msg)
      }
    } finally {
      setSaving(false)
    }
  }

  const isCommunity = mode === 'community'

  if (isCloudMode) {
    return (
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="activity" size={16} className="text-[#00e5c8]" />
          Community Threat Feed
        </h3>
        <div className="p-4 rounded-[12px] border bg-[#1a2235] border-[#2a3650]">
          <p className="text-sm text-[#8b9bc0] mb-2">
            Threat feed sync is configured on each local Navil instance.
          </p>
          <div className="p-3 rounded-lg bg-[#111827] border border-[#2a3650]">
            <code className="text-xs font-mono text-[#00e5c8] block leading-relaxed">
              <span className="text-[#5a6a8a]"># Enable/disable via environment variable:</span>{'\n'}
              export NAVIL_DISABLE_CLOUD_SYNC=false
            </code>
          </div>
          <p className="text-[10px] text-[#5a6a8a] mt-2 flex items-center gap-1">
            <Icon name="info" size={10} />
            Community tier: give-to-get (share to receive). Paid tiers: optional sharing.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
      <div className="flex items-center gap-3 mb-4">
        <h3 className="text-sm font-semibold text-[#f0f4fc] flex items-center gap-2">
          <Icon name="activity" size={16} className="text-[#00e5c8]" />
          Community Threat Feed
        </h3>
        {mode && (
          <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full ${
            isCommunity
              ? 'bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/20'
              : 'bg-violet-500/10 text-violet-400 border border-violet-500/20'
          }`}>
            {isCommunity ? 'Community' : 'Paid'}
          </span>
        )}
        {apiKeyPresent && (
          <span className="px-2 py-0.5 text-[10px] font-medium rounded-full bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/20 flex items-center gap-1">
            <Icon name="lock" size={8} className="text-[#34d399]" />
            Privacy Premium
          </span>
        )}
      </div>

      {enabled === false ? (
        <div className="p-3 rounded-lg bg-[#ff4d6a]/5 border border-[#ff4d6a]/20">
          <div className="flex items-center gap-2 mb-1.5">
            <Icon name="warning" size={14} className="text-[#ff4d6a]" />
            <p className="text-sm text-[#ff4d6a] font-medium">Not sharing — not protected</p>
          </div>
          <p className="text-xs text-[#8b9bc0] leading-relaxed">
            Community threat feed is disabled. Your instance is not receiving real-time
            protection from the network. Enable sharing to join the community feed.
          </p>
        </div>
      ) : !apiKeyPresent ? (
        <div className="p-3 rounded-lg bg-[#00e5c8]/5 border border-[#00e5c8]/20">
          <div className="flex items-center gap-2 mb-1.5">
            <Icon name="check" size={14} className="text-[#00e5c8]" />
            <p className="text-sm text-[#00e5c8] font-medium">Contributing to community feed</p>
          </div>
          <p className="text-xs text-[#8b9bc0] leading-relaxed">
            Sharing anonymous attack metadata and receiving real-time protection.
            Add a Navil Cloud API key for dashboard access and premium features.
          </p>
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-[#f0f4fc]">Share anonymous attack metadata</p>
              <p className="text-xs text-[#5a6a8a] mt-0.5">
                {isCommunity
                  ? 'Give-to-get: share anonymous metadata to receive community threat intelligence.'
                  : 'Share anonymous attack metadata to help protect the global agent ecosystem.'}
              </p>
            </div>
            <button
              onClick={toggle}
              disabled={enabled === null || saving}
              className={`relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-50 ${
                enabled ? 'bg-[#00e5c8]' : 'bg-[#2a3650]'
              }`}
            >
              <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200 ${
                enabled ? 'translate-x-5' : 'translate-x-0'
              }`} />
            </button>
          </div>

          {isCommunity && enabled && (
            <div className="mt-3 p-2.5 rounded-lg bg-[#00e5c8]/5 border border-[#00e5c8]/15">
              <p className="text-[11px] text-[#00e5c8]/80 leading-relaxed">
                Community tier: sharing must stay enabled to receive threat intelligence.
                Upgrade to a paid plan for optional sharing (privacy premium).
              </p>
            </div>
          )}
        </>
      )}

      {error && (
        <div className="mt-3 p-2.5 rounded-lg bg-[#ff4d6a]/5 border border-[#ff4d6a]/20 animate-fadeIn">
          <p className="text-[11px] text-[#ff4d6a] flex items-center gap-1.5">
            <Icon name="warning" size={11} className="text-[#ff4d6a] shrink-0" />
            {error}
          </p>
        </div>
      )}

      <p className="text-[10px] text-[#5a6a8a] mt-3 flex items-center gap-1">
        <Icon name="lock" size={10} className="text-[#5a6a8a]" />
        {isCommunity
          ? 'Community tier: sharing is required to receive threat intelligence.'
          : 'Paid tier: sharing is optional. Controlled by NAVIL_DISABLE_CLOUD_SYNC.'}
      </p>
    </div>
  )
}
