import { useState } from 'react'
import PageHeader from '../components/PageHeader'
import Icon from '../components/Icon'

interface Scope {
  name: string
  description: string
  tools: string[]
}

const DEMO_SCOPES: Scope[] = [
  { name: 'github-pr-review', description: 'Code review agent — read-only PR access', tools: ['pulls/get', 'pulls/list', 'reviews/create'] },
  { name: 'deploy', description: 'Deployment agent — deploy and status only', tools: ['create_deployment', 'get_deployment_status'] },
  { name: 'read-only', description: 'Read-only filesystem access', tools: ['read_file', 'list_directory', 'search_files'] },
  { name: 'default', description: 'Default scope — all tools visible', tools: ['*'] },
]

export default function Scoping() {
  const [scopeName, setScopeName] = useState('')
  const [scopeDescription, setScopeDescription] = useState('')
  const [scopeTools, setScopeTools] = useState('')

  return (
    <div className="space-y-6">
      <PageHeader title="Tool Scoping" subtitle="Context-aware visibility control for MCP tools" />

      {/* Active Scopes */}
      <div>
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="layers" size={16} className="text-[#00e5c8]" />
          Active Scopes
          <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-[#00e5c8]/15 text-[#00e5c8]">
            {DEMO_SCOPES.length}
          </span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {DEMO_SCOPES.map((scope) => (
            <div
              key={scope.name}
              className="glass-card p-5 hover:border-[#00e5c8]/30 transition-colors"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-lg bg-[#00e5c8]/10 border border-[#00e5c8]/20 flex items-center justify-center">
                    <Icon name="layers" size={16} className="text-[#00e5c8]" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-[#f0f4fc] font-mono">{scope.name}</h4>
                    <p className="text-xs text-[#8b9bc0] mt-0.5">{scope.description}</p>
                  </div>
                </div>
                <button
                  disabled
                  className="px-2.5 py-1.5 text-xs text-[#8b9bc0] border border-[#2a3650] rounded-lg opacity-50 cursor-not-allowed min-h-[36px]"
                >
                  Edit
                </button>
              </div>

              <div className="flex items-center gap-2 mb-2.5">
                <Icon name="terminal" size={12} className="text-[#5a6a8a]" />
                <span className="text-[10px] font-semibold text-[#5a6a8a] uppercase tracking-wider">
                  {scope.tools.length} {scope.tools.length === 1 ? 'tool' : 'tools'}
                </span>
              </div>

              <div className="flex flex-wrap gap-1.5">
                {scope.tools.map((tool) => (
                  <span
                    key={tool}
                    className="px-2 py-1 text-xs font-mono bg-[#111827] border border-[#2a3650] rounded-md text-[#8b9bc0]"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Create Scope */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-[#f0f4fc] mb-4 flex items-center gap-2">
          <Icon name="sparkles" size={16} className="text-[#00e5c8]" />
          Create Scope
          <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-[#5a6a8a]/15 text-[#5a6a8a] border border-[#5a6a8a]/30">
            Coming Soon
          </span>
        </h3>

        <div className="space-y-3">
          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Scope Name</label>
            <input
              value={scopeName}
              onChange={e => setScopeName(e.target.value)}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
              placeholder="e.g., ci-pipeline"
            />
          </div>

          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Description</label>
            <input
              value={scopeDescription}
              onChange={e => setScopeDescription(e.target.value)}
              className="w-full bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] focus:border-[#00e5c8] focus:outline-none transition-colors"
              placeholder="e.g., CI/CD pipeline — build and test only"
            />
          </div>

          <div>
            <label className="block text-xs text-[#5a6a8a] font-medium mb-1.5">Tools</label>
            <textarea
              value={scopeTools}
              onChange={e => setScopeTools(e.target.value)}
              className="w-full h-24 bg-[#111827] border border-[#2a3650] rounded-lg px-3 py-2.5 text-sm text-[#f0f4fc] font-mono placeholder:text-[#5a6a8a] focus:border-[#00e5c8] focus:outline-none resize-none transition-colors"
              placeholder="One tool per line or comma-separated, e.g.:&#10;build_project&#10;run_tests&#10;get_status"
            />
          </div>

          <button
            disabled
            className="w-full px-4 py-2.5 bg-[#00e5c8] text-[#0a0e17] rounded-lg text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-200 min-h-[44px]"
          >
            <Icon name="layers" size={14} />
            Create Scope
          </button>

          <p className="text-xs text-[#5a6a8a] text-center">
            Scope creation via the dashboard is not yet available. Define scopes in <span className="font-mono text-[#8b9bc0]">policy.yaml</span> for now.
          </p>
        </div>
      </div>
    </div>
  )
}
