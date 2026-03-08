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
        // Map internal provider names back to UI values
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
      // Send current form values so the test uses what's on screen, not the saved config
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
    ? (model.trim() || true)  // Ollama always saveable — no key needed
    : isCompatible
      ? baseUrl.trim() && (apiKey.trim() || config?.api_key_set)
      : apiKey.trim()

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Configure Navil preferences" />

      {/* LLM Configuration */}
      <div className="glass-card p-6 animate-slideUp opacity-0 stagger-2">
        <h3 className="text-sm font-medium text-gray-300 mb-5 flex items-center gap-2">
          <Icon name="sparkles" size={16} className="text-violet-400" />
          LLM Configuration
        </h3>

        {/* Connection status */}
        {config && (
          <div className={`mb-5 p-3 rounded-lg border flex items-center gap-3 ${
            config.api_key_set
              ? 'bg-emerald-500/5 border-emerald-500/20'
              : 'bg-amber-500/5 border-amber-500/20'
          }`}>
            <div className={`w-2 h-2 rounded-full ${config.api_key_set ? 'bg-emerald-400' : 'bg-amber-400'}`} />
            <div>
              <p className={`text-sm ${config.api_key_set ? 'text-emerald-400' : 'text-amber-400'}`}>
                {config.api_key_set ? 'Connected' : 'Not configured'}
              </p>
              {config.api_key_set && (
                <p className="text-xs text-gray-500">
                  Provider: {config.provider} · Model: {config.model}
                  {config.base_url ? ` · ${config.base_url}` : ''}
                </p>
              )}
            </div>
          </div>
        )}

        {config && !config.available && (
          <div className="mb-5 p-3 rounded-lg border bg-red-500/5 border-red-500/20 flex items-center gap-3">
            <Icon name="warning" size={14} className="text-red-400 shrink-0" />
            <div>
              <p className="text-sm text-red-400">LLM SDKs not installed</p>
              <p className="text-xs text-gray-500">
                Install with: <code className="font-mono text-red-400/80">pip install navil[llm]</code>
              </p>
            </div>
          </div>
        )}

        <div className="space-y-4">
          {/* Provider */}
          <div>
            <label className="block text-xs text-gray-500 mb-1.5">Provider</label>
            <select
              value={provider}
              onChange={e => { setProvider(e.target.value); setSaveResult(null); setTestResult(null) }}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-cyan-500 focus:outline-none"
            >
              {providers.map(p => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
            <p className="text-xs text-gray-600 mt-1">
              {isOllama
                ? 'Runs locally — no API key needed. Make sure Ollama is running on your machine.'
                : isCompatible
                  ? 'Works with OpenRouter, Together AI, Groq, DeepSeek, Fireworks, and any OpenAI-compatible API'
                  : <>Or set via environment variable: <code className="font-mono text-gray-500">{selectedHint}</code></>
              }
            </p>
          </div>

          {/* Base URL — only for OpenAI Compatible */}
          {isCompatible && (
            <div>
              <label className="block text-xs text-gray-500 mb-1.5">Base URL</label>
              <input
                value={baseUrl}
                onChange={e => { setBaseUrl(e.target.value); setSaveResult(null) }}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-cyan-500 focus:outline-none font-mono"
                placeholder="https://api.example.com/v1"
                
              />
              <div className="flex flex-wrap gap-1.5 mt-2">
                {compatibleExamples.map(ex => (
                  <button
                    key={ex.name}
                    onClick={() => { setBaseUrl(ex.url); setSaveResult(null) }}
                    className="px-2 py-0.5 text-[10px] bg-gray-800 text-gray-400 border border-gray-700 rounded hover:border-gray-600 hover:text-gray-300"
                  >
                    {ex.name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Model override — for compatible/ollama or when user wants to customize */}
          {(isCompatible || isOllama) && (
            <div>
              <label className="block text-xs text-gray-500 mb-1.5">Model {!isOllama && <span className="text-gray-600">(optional)</span>}</label>
              <input
                value={model}
                onChange={e => { setModel(e.target.value); setSaveResult(null) }}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-cyan-500 focus:outline-none font-mono"
                placeholder={isOllama ? 'e.g., llama3.2, deepseek-r1:70b, qwen3' : 'e.g., anthropic/claude-sonnet-4, deepseek-chat, llama-3.1-70b'}
                
              />
            </div>
          )}

          {/* API Key — hidden for Ollama */}
          {!isOllama && <div>
            <label className="block text-xs text-gray-500 mb-1.5">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={e => { setApiKey(e.target.value); setSaveResult(null) }}
              onKeyDown={e => e.key === 'Enter' && handleSave()}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-cyan-500 focus:outline-none font-mono"
              placeholder={config?.api_key_set ? '••••••••  (key is set — enter new to replace)' : 'Paste your API key here'}
              
            />
            <p className="text-xs text-gray-600 mt-1 flex items-center gap-1">
              <Icon name="lock" size={10} className="text-gray-600" />
              Stored in memory only. Not persisted to disk.
            </p>
          </div>}

          {/* Buttons */}
          <div className="flex gap-3 pt-1">
            <button
              onClick={handleSave}
              disabled={!canSave || saving}
              className="px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <Icon name="check" size={14} />
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button
              onClick={handleTest}
              disabled={testing || (!config?.api_key_set && !isOllama && !apiKey.trim())}
              className="px-4 py-2 bg-gray-800 text-gray-300 border border-gray-700 rounded-lg text-sm font-medium hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <Icon name="activity" size={14} className={testing ? 'animate-spin' : ''} />
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
          </div>

          {/* Result messages */}
          {saveResult && (
            <div className={`p-3 rounded-lg border animate-fadeIn ${
              saveResult.ok ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/5 border-red-500/20'
            }`}>
              <p className={`text-sm flex items-center gap-2 ${saveResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                <Icon name={saveResult.ok ? 'check' : 'warning'} size={14} />
                {saveResult.msg}
              </p>
            </div>
          )}
          {testResult && (
            <div className={`p-3 rounded-lg border animate-fadeIn ${
              testResult.ok ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/5 border-red-500/20'
            }`}>
              <p className={`text-sm flex items-center gap-2 ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
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
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Icon name="info" size={16} className="text-gray-400" />
          About
        </h3>
        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500">Version</span>
            <span className="text-gray-300 font-mono">{import.meta.env.VITE_APP_VERSION || '0.1.0'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">LLM SDK</span>
            <span className={`font-mono ${config?.available ? 'text-emerald-400' : 'text-red-400'}`}>
              {config?.available ? 'Installed' : 'Not installed'}
            </span>
          </div>
          {config?.api_key_set && (
            <>
              <div className="flex justify-between">
                <span className="text-gray-500">Active Provider</span>
                <span className="text-gray-300 font-mono">{config.provider}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Active Model</span>
                <span className="text-gray-300 font-mono">{config.model}</span>
              </div>
              {config.base_url && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Base URL</span>
                  <span className="text-gray-300 font-mono text-xs truncate max-w-[250px]">{config.base_url}</span>
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
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api.getTelemetrySettings()
      .then(r => setEnabled(r.cloud_sync_enabled))
      .catch(() => setEnabled(false))
  }, [])

  const toggle = async () => {
    if (enabled === null) return
    setSaving(true)
    try {
      const res = await api.updateTelemetrySettings(!enabled)
      setEnabled(res.cloud_sync_enabled)
    } catch { /* ignore */ }
    finally { setSaving(false) }
  }

  return (
    <div className="glass-card p-6 animate-slideUp opacity-0 stagger-3">
      <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
        <Icon name="activity" size={16} className="text-cyan-400" />
        Community Threat Feed
      </h3>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-300">Share anonymous attack metadata</p>
          <p className="text-xs text-gray-500 mt-0.5">
            Share anonymous attack metadata to help protect the global agent ecosystem.
          </p>
        </div>
        <button
          onClick={toggle}
          disabled={enabled === null || saving}
          className={`relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-50 ${
            enabled ? 'bg-cyan-500' : 'bg-gray-700'
          }`}
        >
          <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200 ${
            enabled ? 'translate-x-5' : 'translate-x-0'
          }`} />
        </button>
      </div>
      <p className="text-[10px] text-gray-600 mt-3 flex items-center gap-1">
        <Icon name="lock" size={10} className="text-gray-600" />
        Controlled by NAVIL_DISABLE_CLOUD_SYNC environment variable.
      </p>
    </div>
  )
}
