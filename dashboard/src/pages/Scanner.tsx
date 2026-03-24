import { useState } from 'react'
import { api, ScanResult, ConfigAnalysis, Vulnerability } from '../api'
import useSessionState from '../hooks/useSessionState'
import useNavilStream from '../hooks/useNavilStream'
import SeverityBadge from '../components/SeverityBadge'
import PageHeader from '../components/PageHeader'
import ScoreGauge from '../components/ScoreGauge'
import MiniBar from '../components/MiniBar'
import Icon from '../components/Icon'
import LLMErrorCard from '../components/LLMErrorCard'
import UpgradePrompt from '../components/UpgradePrompt'
import useLLMAvailable from '../hooks/useLLMAvailable'

// ── Fix suggestions by vulnerability ID prefix ────────────────────
interface FixSuggestion {
  steps: string[]
  configExample?: string
}

function getFixSuggestion(vuln: Vulnerability): FixSuggestion {
  const id = vuln.id || ''
  const field = vuln.affected_field || ''

  // Credential findings
  if (id.startsWith('CRED-')) {
    return {
      steps: [
        'Remove hardcoded credentials from your configuration file immediately.',
        'Store secrets in environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).',
        'Reference secrets via environment variable syntax: {"$env": "MY_SECRET_KEY"}',
        'Rotate the exposed credential since it may have been committed to version control.',
      ],
      configExample: `"credentials": {\n  "source": "environment",\n  "vault_path": "secret/mcp"\n}`,
    }
  }

  // Permission findings
  if (id === 'PERM-OVERPRIVILEGED') {
    return {
      steps: [
        'Replace wildcard ("*") permissions with specific, named permissions.',
        'List only the exact permissions each tool needs to function.',
        'Audit each tool\'s actual usage to determine minimal required permissions.',
      ],
      configExample: `"permissions": ["read", "list"]  // instead of ["*"]`,
    }
  }
  if (id === 'PERM-UNRESTRICTED-FS') {
    return {
      steps: [
        'Restrict file system access to specific directories using allowed_paths.',
        'Add explicit denied_paths for sensitive directories (/etc, /root, ~/.ssh).',
        'Limit file type access where possible (e.g. only .json, .txt files).',
      ],
      configExample: `"file_system": {\n  "permissions": ["read"],\n  "allowed_paths": ["/data/safe"],\n  "denied_paths": ["/etc", "/root", "/home/*/.ssh"]\n}`,
    }
  }

  // Authentication findings
  if (id === 'AUTH-MISSING') {
    return {
      steps: [
        'Add an authentication block to your server configuration.',
        'For HTTP deployments, use mTLS, OAuth2, or API key authentication.',
        'For local stdio servers, authentication is typically not required.',
      ],
      configExample: `"authentication": {\n  "enabled": true,\n  "method": "mtls",\n  "certificate_path": "/etc/certs/server.pem"\n}`,
    }
  }
  if (id === 'AUTH-DISABLED') {
    return {
      steps: [
        'Set "enabled": true in the authentication configuration.',
        'Choose an appropriate auth method for your deployment model.',
      ],
      configExample: `"authentication": {\n  "enabled": true,\n  "method": "api_key",\n  "key_rotation": { "interval_days": 90 }\n}`,
    }
  }

  // Source verification
  if (id === 'SRC-UNVERIFIED') {
    return {
      steps: [
        'Pin server dependencies to exact versions instead of using "latest" or ranges.',
        'Add checksum or signature verification fields when available.',
        'Use trusted registries and verify package provenance.',
      ],
      configExample: `"server": {\n  "source": "npm:@modelcontextprotocol/server@1.2.3",\n  "verified": true,\n  "signature": "sha256:abc123..."\n}`,
    }
  }

  // Malicious patterns
  if (id.startsWith('MAL-')) {
    return {
      steps: [
        'Remove or rename tools with suspicious action names (exfiltrate, destroy_data, steal, etc.).',
        'Audit tool definitions for hidden malicious capabilities.',
        'If this is a legitimate tool name, rename it to avoid triggering security scanners.',
      ],
    }
  }

  // Network security
  if (id === 'NET-INSECURE-PROTOCOL') {
    return {
      steps: [
        'Switch from HTTP to HTTPS for all server connections.',
        'Configure TLS certificates for the server.',
        'Bind to 127.0.0.1 instead of 0.0.0.0 if the server is local-only.',
      ],
      configExample: `"server": {\n  "protocol": "https",\n  "host": "127.0.0.1",\n  "port": 8443\n}`,
    }
  }
  if (id === 'NET-EXPOSED-HOST') {
    return {
      steps: [
        'Change host from 0.0.0.0 to 127.0.0.1 for local-only deployments.',
        'If external access is needed, use a reverse proxy with TLS and auth.',
      ],
      configExample: `"server": {\n  "host": "127.0.0.1"  // instead of "0.0.0.0"\n}`,
    }
  }

  // Prompt injection
  if (id.startsWith('PROMPT-INJECTION')) {
    return {
      steps: [
        'Review tool descriptions for instruction-override language.',
        'Remove phrases like "ignore previous instructions" or "you are now...".',
        'Sanitize all user-facing text in tool definitions.',
        'Add input validation to filter prompt injection attempts in tool arguments.',
      ],
    }
  }

  // Data exfiltration risk
  if (id === 'EXFIL-RISK') {
    return {
      steps: [
        'Separate file-read and network-send capabilities into different server instances.',
        'Add rate limiting to network-capable tools.',
        'Restrict outbound network access to specific domains via allowlists.',
      ],
    }
  }

  // Privilege escalation
  if (id.startsWith('PRIVESC')) {
    return {
      steps: [
        'Remove or restrict tools that allow command execution or shell access.',
        'If command execution is required, use a sandboxed environment.',
        'Add an allowlist of permitted commands instead of open shell access.',
      ],
    }
  }

  // Supply chain
  if (id.startsWith('SUPPLY-CHAIN')) {
    return {
      steps: [
        'Pin all package versions to exact semver instead of ranges or "latest".',
        'Use packages from trusted scopes (@modelcontextprotocol, @anthropic, etc.).',
        'Avoid pipe-to-shell install patterns (curl | sh).',
        'Verify package checksums before installation.',
      ],
    }
  }

  // Sensitive data exposure
  if (id.startsWith('SENSITIVE-DATA')) {
    return {
      steps: [
        'Remove direct access to environment variables and secrets from tool permissions.',
        'Use a secrets proxy that provides only the specific values needed.',
        'Restrict which env vars a tool can access via an allowlist.',
      ],
    }
  }

  // Excessive permissions
  if (id.startsWith('EXCESSIVE-PERM')) {
    return {
      steps: [
        'Narrow the scope of each permission to the minimum required.',
        'Replace broad terms like "full access" or "unrestricted" with specific grants.',
        'Document why each permission is needed for audit purposes.',
      ],
    }
  }

  // Fallback: derive steps from the existing remediation text
  return {
    steps: [
      vuln.remediation || 'Review and address this finding based on the description above.',
      `Check the affected field "${field}" in your configuration.`,
    ],
  }
}

// ── Policy YAML generation ────────────────────────────────────────
function generatePolicyRule(vuln: Vulnerability): string {
  const id = vuln.id || 'UNKNOWN'
  const field = vuln.affected_field || '*'

  if (id.startsWith('CRED-')) {
    return [
      `# Block plaintext credentials (${id})`,
      `- rule: deny_plaintext_credentials`,
      `  match:`,
      `    field_pattern: "${field}"`,
      `    contains: ["api_key", "password", "token", "secret"]`,
      `  action: block`,
      `  message: "Plaintext credentials detected \u2014 use environment variables or a vault"`,
    ].join('\n')
  }

  if (id === 'PERM-OVERPRIVILEGED' || id === 'PERM-UNRESTRICTED-FS') {
    return [
      `# Restrict overprivileged permissions (${id})`,
      `- rule: deny_wildcard_permissions`,
      `  match:`,
      `    field_pattern: "tools.*.permissions"`,
      `    value: ["*", "all", "unrestricted"]`,
      `  action: block`,
      `  message: "Wildcard permissions are not allowed \u2014 use explicit permission lists"`,
    ].join('\n')
  }

  if (id === 'AUTH-MISSING' || id === 'AUTH-DISABLED') {
    return [
      `# Require authentication (${id})`,
      `- rule: require_authentication`,
      `  match:`,
      `    field: "authentication.enabled"`,
      `    value: false`,
      `  action: warn`,
      `  message: "Authentication should be enabled for network-exposed servers"`,
    ].join('\n')
  }

  if (id === 'NET-INSECURE-PROTOCOL' || id === 'NET-EXPOSED-HOST') {
    return [
      `# Enforce secure network config (${id})`,
      `- rule: require_secure_transport`,
      `  match:`,
      `    any:`,
      `      - field: "server.protocol"`,
      `        value: "http"`,
      `      - field: "server.host"`,
      `        value: "0.0.0.0"`,
      `  action: block`,
      `  message: "Use HTTPS and bind to 127.0.0.1 for local servers"`,
    ].join('\n')
  }

  if (id.startsWith('MAL-')) {
    return [
      `# Block malicious patterns (${id})`,
      `- rule: deny_malicious_tools`,
      `  match:`,
      `    field_pattern: "tools.*"`,
      `    name_contains: ["exfiltrate", "destroy_data", "steal", "backdoor"]`,
      `  action: block`,
      `  message: "Tool name matches known malicious patterns"`,
    ].join('\n')
  }

  if (id.startsWith('PROMPT-INJECTION')) {
    return [
      `# Block prompt injection in tool descriptions (${id})`,
      `- rule: deny_prompt_injection`,
      `  match:`,
      `    field_pattern: "tools.*.description"`,
      `    regex: "(?i)(ignore previous|you are now|act as|disregard)"`,
      `  action: block`,
      `  message: "Tool description contains prompt injection patterns"`,
    ].join('\n')
  }

  if (id === 'EXFIL-RISK') {
    return [
      `# Mitigate data exfiltration risk (${id})`,
      `- rule: limit_combined_capabilities`,
      `  match:`,
      `    has_both:`,
      `      - capability: "file_read"`,
      `      - capability: "network_send"`,
      `  action: warn`,
      `  message: "Server has both file read and network send \u2014 exfiltration risk"`,
    ].join('\n')
  }

  if (id.startsWith('PRIVESC')) {
    return [
      `# Restrict privilege escalation (${id})`,
      `- rule: deny_shell_access`,
      `  match:`,
      `    field_pattern: "tools.*"`,
      `    capability: ["execute_command", "shell_access", "run_script"]`,
      `  action: block`,
      `  message: "Shell/command execution tools require explicit approval"`,
    ].join('\n')
  }

  if (id.startsWith('SUPPLY-CHAIN')) {
    return [
      `# Enforce supply chain security (${id})`,
      `- rule: require_pinned_versions`,
      `  match:`,
      `    field_pattern: "server.source"`,
      `    lacks: ["version_pin", "checksum"]`,
      `  action: warn`,
      `  message: "Pin package versions and verify checksums"`,
    ].join('\n')
  }

  // Generic fallback
  return [
    `# Address finding: ${vuln.title} (${id})`,
    `- rule: custom_${id.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
    `  match:`,
    `    field: "${field}"`,
    `  action: warn`,
    `  message: "${(vuln.remediation || vuln.title).replace(/"/g, '\\"')}"`,
  ].join('\n')
}

const SAMPLE_VULNERABLE = JSON.stringify({
  server: { name: "vulnerable-mcp", protocol: "http", host: "0.0.0.0", port: 8080 },
  authentication: { enabled: false },
  tools: {
    file_system: { permissions: ["*"], paths: ["/"] },
    network_access: { allowed_actions: ["read", "exfiltrate", "destroy_data"] }
  },
  credentials: { api_key: "sk-1234567890abcdef", password: "admin123" }
}, null, 2)

const SAMPLE_SECURE = JSON.stringify({
  server: { name: "secure-mcp", protocol: "https", host: "127.0.0.1", port: 8443 },
  authentication: { enabled: true, method: "mtls", certificate_path: "/etc/certs/server.pem" },
  tools: {
    file_system: { permissions: ["read"], allowed_paths: ["/data/safe"], denied_paths: ["/etc", "/root"] },
    logs: { permissions: ["read"], rate_limit: { requests_per_minute: 30 } }
  },
  credentials: { source: "environment", vault_path: "secret/mcp" }
}, null, 2)

const levelBarColor: Record<string, string> = {
  CRITICAL: 'bg-[#ff4d6a]',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-[#f59e0b]',
  LOW: 'bg-[#3b82f6]',
}

const levelBorderColor: Record<string, string> = {
  CRITICAL: 'border-l-[#ff4d6a]',
  HIGH: 'border-l-orange-500',
  MEDIUM: 'border-l-[#f59e0b]',
  LOW: 'border-l-[#3b82f6]',
}

export default function Scanner() {
  const { canUseLLM } = useLLMAvailable()
  const [config, setConfig] = useSessionState('scanner_config', '')
  const [result, setResult] = useSessionState<ScanResult | null>('scanner_result', null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [analysis, setAnalysis] = useSessionState<ConfigAnalysis | null>('scanner_analysis', null)
  const [analysisError, setAnalysisError] = useState<{ message: string; type: string } | null>(null)
  const stream = useNavilStream<ConfigAnalysis>()

  // How-to-fix panel state
  const [expandedFix, setExpandedFix] = useState<string | null>(null)
  const [policyVulnId, setPolicyVulnId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [savingPolicyId, setSavingPolicyId] = useState<string | null>(null)
  const [savedPolicyId, setSavedPolicyId] = useState<string | null>(null)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  const showToast = (message: string, type: 'success' | 'error') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 5000)
  }

  const handleCopyPolicy = (vulnKey: string, yaml: string) => {
    navigator.clipboard.writeText(yaml)
    setCopiedId(vulnKey)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleSavePolicy = async (vulnKey: string, yaml: string) => {
    setSavingPolicyId(vulnKey)
    setSavedPolicyId(null)
    try {
      await api.savePolicy(yaml)
      setSavedPolicyId(vulnKey)
      showToast('Policy rule saved to ~/.navil/policy.auto.yaml', 'success')
      setTimeout(() => setSavedPolicyId(null), 4000)
    } catch {
      showToast('Failed to save policy \u2014 is the backend running?', 'error')
    } finally {
      setSavingPolicyId(null)
    }
  }

  const doScan = async () => {
    setError('')
    setResult(null)
    setAnalysis(null)
    setAnalysisError(null)
    setExpandedFix(null)
    setPolicyVulnId(null)
    stream.abort()
    setLoading(true)
    try {
      const parsed = JSON.parse(config)
      const res = await api.scan(parsed)
      setResult(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Config Scanner" subtitle="Analyze MCP server configurations for vulnerabilities" />

      <div className="flex gap-2">
        <button
          onClick={() => setConfig(SAMPLE_VULNERABLE)}
          className="px-3 py-1.5 text-xs bg-[#ff4d6a]/15 text-[#ff4d6a] border border-[#ff4d6a]/30 rounded-lg hover:bg-[#ff4d6a]/25 flex items-center gap-1.5"
        >
          <Icon name="unlock" size={13} />
          Load Vulnerable Sample
        </button>
        <button
          onClick={() => setConfig(SAMPLE_SECURE)}
          className="px-3 py-1.5 text-xs bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 rounded-lg hover:bg-[#34d399]/25 flex items-center gap-1.5"
        >
          <Icon name="lock" size={13} />
          Load Secure Sample
        </button>
      </div>

      <div className="relative">
        <textarea
          value={config}
          onChange={e => setConfig(e.target.value)}
          placeholder="Paste your MCP server configuration JSON here..."
          className="w-full h-64 bg-[#1a2235] border border-[#2a3650] rounded-[12px] p-4 pr-10 font-mono text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none resize-y leading-7 placeholder:text-[#5a6a8a] transition-colors"
        />
        {config && (
          <button
            onClick={() => { setConfig(''); setResult(null); setAnalysis(null); setAnalysisError(null); setError(''); stream.abort() }}
            className="absolute top-3 right-3 w-7 h-7 rounded-lg bg-[#2a3650] border border-[#5a6a8a]/30 hover:bg-[#ff4d6a]/20 hover:border-[#ff4d6a]/40 flex items-center justify-center text-[#8b9bc0] hover:text-[#ff4d6a] transition-colors z-10"
            title="Clear"
          >
            <Icon name="x" size={14} />
          </button>
        )}
      </div>

      <div className="relative inline-block">
        <button
          onClick={doScan}
          disabled={loading || !config.trim()}
          className="px-6 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg font-semibold hover:bg-[#00b8a0] hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition-all duration-200"
        >
          {loading && !result ? (
            <>
              <Icon name="scan" size={16} className="animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Icon name="scan" size={16} />
              Scan Configuration
            </>
          )}
        </button>
        {loading && !result && (
          <div className="absolute inset-0 rounded-lg bg-[#00e5c8]/20 animate-pulseGlow pointer-events-none" />
        )}
      </div>

      {error && <p className="text-[#ff4d6a] text-sm">{error}</p>}

      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Score + Breakdown */}
          <div className="glass-card p-8 flex flex-col sm:flex-row items-center gap-8">
            <ScoreGauge score={result.security_score} size={160} />
            <div className="flex-1 space-y-3">
              <p className="text-lg text-[#f0f4fc]">
                <span className="font-bold">{result.total_vulnerabilities}</span> vulnerabilities found
              </p>
              <p className="text-sm text-[#5a6a8a] leading-relaxed">{result.recommendation}</p>
              {/* Severity breakdown bars */}
              <div className="space-y-2 mt-4">
                {Object.entries(result.vulnerabilities_by_level).map(([level, count]) => (
                  count > 0 && (
                    <div key={level} className="flex items-center gap-3">
                      <SeverityBadge severity={level} />
                      <MiniBar
                        value={count as number}
                        max={result.total_vulnerabilities}
                        color={levelBarColor[level] || 'bg-[#5a6a8a]'}
                        className="flex-1"
                      />
                      <span className="text-xs text-[#5a6a8a] w-6 text-right">{count as number}</span>
                    </div>
                  )
                ))}
              </div>
            </div>
          </div>

          {/* Vulnerabilities list */}
          {result.vulnerabilities.length > 0 && (
            <div className="space-y-3">
              {result.vulnerabilities.map((vuln, i) => {
                const vulnKey = vuln.id || `vuln-${i}`
                const isFixExpanded = expandedFix === vulnKey
                const isPolicyShown = policyVulnId === vulnKey
                const fix = getFixSuggestion(vuln)
                const policyYaml = generatePolicyRule(vuln)
                return (
                <div
                  key={vulnKey}
                  className={`glass-card border-l-2 ${levelBorderColor[vuln.risk_level] || 'border-l-[#5a6a8a]'} p-4 hover:shadow-lg hover:shadow-black/20 animate-slideUp opacity-0`}
                  style={{ animationDelay: `${i * 0.08}s` }}
                >
                  <div className="flex items-start gap-3">
                    <Icon name="warning" size={16} className="text-[#5a6a8a] mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={vuln.risk_level} />
                        <p className="font-medium text-[#f0f4fc]">{vuln.title}</p>
                      </div>
                      <p className="text-sm text-[#8b9bc0] mt-1">{vuln.description}</p>
                      <p className="text-sm text-[#00e5c8] mt-2">
                        <span className="text-[#5a6a8a]">Remediation:</span> {vuln.remediation}
                      </p>

                      {/* How to Fix toggle */}
                      <button
                        onClick={() => { setExpandedFix(isFixExpanded ? null : vulnKey); setPolicyVulnId(null) }}
                        className="mt-3 px-3 py-1.5 text-xs bg-[#00e5c8]/10 text-[#00e5c8] border border-[#00e5c8]/25 rounded-lg hover:bg-[#00e5c8]/20 flex items-center gap-1.5 transition-colors"
                      >
                        <Icon name={isFixExpanded ? 'chevron-down' : 'chevron-right'} size={12} />
                        How to Fix
                      </button>

                      {/* Expanded fix details */}
                      {isFixExpanded && (
                        <div className="mt-3 space-y-3 animate-fadeIn">
                          {/* Step-by-step remediation */}
                          <div className="bg-[#0d1117] rounded-lg p-4 border border-[#2a3650]/60">
                            <p className="text-xs font-semibold text-[#f0f4fc] mb-2 flex items-center gap-1.5">
                              <Icon name="shield" size={13} className="text-[#00e5c8]" />
                              Remediation Steps
                            </p>
                            <ol className="space-y-2 list-none">
                              {fix.steps.map((step, si) => (
                                <li key={si} className="text-sm text-[#8b9bc0] flex items-start gap-2">
                                  <span className="text-[#00e5c8] font-mono text-xs mt-0.5 shrink-0">{si + 1}.</span>
                                  {step}
                                </li>
                              ))}
                            </ol>
                          </div>

                          {/* Config example */}
                          {fix.configExample && (
                            <div className="bg-[#0d1117] rounded-lg p-4 border border-[#2a3650]/60">
                              <p className="text-xs font-semibold text-[#f0f4fc] mb-2 flex items-center gap-1.5">
                                <Icon name="code" size={13} className="text-[#3b82f6]" />
                                Example Config
                              </p>
                              <pre className="text-xs text-[#8b9bc0] font-mono whitespace-pre-wrap">{fix.configExample}</pre>
                            </div>
                          )}

                          {/* Fix with Policy button */}
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setPolicyVulnId(isPolicyShown ? null : vulnKey)}
                              className="px-3 py-1.5 text-xs bg-violet-500/15 text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/25 flex items-center gap-1.5 transition-colors"
                            >
                              <Icon name="shield" size={12} />
                              {isPolicyShown ? 'Hide Policy Rule' : 'Fix with Policy'}
                            </button>
                          </div>

                          {/* Policy YAML */}
                          {isPolicyShown && (
                            <div className="bg-[#0d1117] rounded-lg p-4 border border-violet-500/20 animate-fadeIn">
                              <div className="flex items-center justify-between mb-2">
                                <p className="text-xs font-semibold text-[#f0f4fc] flex items-center gap-1.5">
                                  <Icon name="document" size={13} className="text-violet-400" />
                                  Navil Policy Rule
                                </p>
                                <div className="flex items-center gap-1.5">
                                  <button
                                    onClick={() => handleCopyPolicy(vulnKey, policyYaml)}
                                    className="px-2 py-1 text-[10px] bg-[#2a3650] text-[#8b9bc0] rounded hover:bg-[#3a4660] flex items-center gap-1 transition-colors"
                                  >
                                    <Icon name={copiedId === vulnKey ? 'check' : 'copy'} size={10} />
                                    {copiedId === vulnKey ? 'Copied' : 'Copy'}
                                  </button>
                                  <button
                                    onClick={() => handleSavePolicy(vulnKey, policyYaml)}
                                    disabled={savingPolicyId === vulnKey}
                                    className="px-2 py-1 text-[10px] bg-violet-500/20 text-violet-400 rounded hover:bg-violet-500/30 flex items-center gap-1 transition-colors disabled:opacity-50"
                                  >
                                    <Icon name={savedPolicyId === vulnKey ? 'check' : 'shield'} size={10} />
                                    {savingPolicyId === vulnKey ? 'Saving...' : savedPolicyId === vulnKey ? 'Saved!' : 'Save to policy.yaml'}
                                  </button>
                                </div>
                              </div>
                              <pre className="text-xs text-violet-300/80 font-mono whitespace-pre-wrap">{policyYaml}</pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                )
              })}
            </div>
          )}

          {/* AI Deep Analysis */}
          <div className="glass-card p-6 animate-slideUp opacity-0" style={{ animationDelay: '0.3s' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-[#f0f4fc] flex items-center gap-2">
                <Icon name="sparkles" size={16} className="text-violet-400" />
                AI Deep Analysis
              </h3>
              {!analysis && !stream.result && canUseLLM && (
                <button
                  onClick={() => {
                    setAnalysisError(null)
                    try {
                      const parsed = JSON.parse(config)
                      stream.start({
                        endpoint: '/llm/analyze-config',
                        body: { config: parsed },
                        onDone: (res) => setAnalysis(res),
                        onError: (msg) => setAnalysisError({ message: msg, type: 'unknown' }),
                      })
                    } catch (e: unknown) {
                      setAnalysisError({ message: e instanceof Error ? e.message : String(e), type: 'unknown' })
                    }
                  }}
                  disabled={stream.streaming}
                  className="px-3 py-1.5 text-xs bg-violet-500/15 text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/25 flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Icon name="sparkles" size={13} className={stream.streaming ? 'animate-spin' : ''} />
                  {stream.streaming ? 'Analyzing...' : 'Run AI Analysis'}
                </button>
              )}
            </div>

            {!canUseLLM && !analysis && !analysisError && !stream.streaming && (
              <UpgradePrompt feature="AI Deep Analysis" compact />
            )}

            {(analysisError || stream.error) && (
              <LLMErrorCard
                message={(analysisError?.message || stream.error)!}
                errorType={(analysisError?.type || 'unknown') as any}
                onRetry={() => {
                  setAnalysisError(null)
                  try {
                    const parsed = JSON.parse(config)
                    stream.start({
                      endpoint: '/llm/analyze-config',
                      body: { config: parsed },
                      onDone: (res) => setAnalysis(res),
                      onError: (msg) => setAnalysisError({ message: msg, type: 'unknown' }),
                    })
                  } catch { /* JSON parse error already shown */ }
                }}
              />
            )}

            {/* Streaming text */}
            {stream.streaming && stream.text && !analysis && (
              <div className="animate-fadeIn">
                <pre className="text-sm text-[#8b9bc0] whitespace-pre-wrap font-mono bg-[#0d1117] rounded-lg p-3 max-h-48 overflow-y-auto">
                  {stream.text}
                  <span className="animate-pulse text-violet-400">|</span>
                </pre>
              </div>
            )}

            {(analysis || stream.result) && (() => {
              const a = analysis || stream.result!
              // Normalize unknown severity — if scan found 0 vulns, override to OK
              const displaySeverity = (a.severity?.toUpperCase() === 'UNKNOWN' && result?.total_vulnerabilities === 0)
                ? 'OK'
                : a.severity
              return (
              <div className="space-y-4 animate-fadeIn">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={displaySeverity} />
                  {a.confidence !== undefined && (
                    <div className="flex items-center gap-2">
                      <MiniBar value={a.confidence * 100} max={100} color="bg-violet-500" height="h-1" className="w-20" />
                      <span className="text-xs text-[#5a6a8a]">{(a.confidence * 100).toFixed(0)}% confidence</span>
                    </div>
                  )}
                  {stream.cached && (
                    <span className="text-[10px] text-[#5a6a8a] bg-[#111827] px-1.5 py-0.5 rounded">cached</span>
                  )}
                </div>
                <p className="text-sm text-[#f0f4fc]">{a.explanation}</p>
                {a.risks.length > 0 && (
                  <div>
                    <p className="text-xs text-[#5a6a8a] mb-2">Identified Risks</p>
                    <ul className="space-y-1.5">
                      {a.risks.map((risk, j) => (
                        <li key={j} className="text-sm text-orange-400 flex items-start gap-2">
                          <Icon name="warning" size={12} className="text-orange-500 mt-0.5 shrink-0" />
                          {risk}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {a.remediations.length > 0 && (
                  <div>
                    <p className="text-xs text-[#5a6a8a] mb-2">Remediations</p>
                    <ul className="space-y-1.5">
                      {a.remediations.map((rem, j) => (
                        <li key={j} className="text-sm text-[#00e5c8] flex items-start gap-2">
                          <Icon name="check" size={12} className="text-[#00e5c8] mt-0.5 shrink-0" />
                          {rem}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
              )
            })()}
          </div>
        </div>
      )}

      {/* Toast notification */}
      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg shadow-lg animate-fadeIn flex items-center gap-2 text-sm ${
          toast.type === 'success'
            ? 'bg-[#00e5c8]/15 text-[#00e5c8] border border-[#00e5c8]/30'
            : 'bg-[#ff4d6a]/15 text-[#ff4d6a] border border-[#ff4d6a]/30'
        }`}>
          <Icon name={toast.type === 'success' ? 'check' : 'warning'} size={14} />
          {toast.message}
        </div>
      )}
    </div>
  )
}
