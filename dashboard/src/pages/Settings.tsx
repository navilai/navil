import { useEffect, useState } from 'react'
import { api, LLMConfig } from '../api'
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

  const isOllama = provider === 'ollama'
  const isCompatible = provider === 'openai_compatible'

  useEffect(() => {
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
      </div>

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
            <span className={`font-mono ${config?.available ? 'text-[#34d399]' : 'text-[#ff4d6a]'}`}>
              {config?.available ? 'Installed' : 'Not installed'}
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
        </div>
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
            In community mode, sync must stay enabled to receive threat intelligence updates.
            Add a Navil Cloud API key to gain independent control over sync.
          </p>
        </div>
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
        Controlled by NAVIL_DISABLE_CLOUD_SYNC environment variable.
      </p>
    </div>
  )
}
