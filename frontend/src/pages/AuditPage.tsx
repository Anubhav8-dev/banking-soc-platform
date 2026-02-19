import React, { useState } from 'react'
import { Search, FileText, Download } from 'lucide-react'
import { getAuditTrail } from '../utils/api'

export default function AuditPage() {
  const [incidentId, setIncidentId] = useState('')
  const [trail, setTrail] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSearch = async () => {
    if (!incidentId.trim()) return
    setLoading(true)
    setError('')
    try {
      const res = await getAuditTrail(incidentId.trim())
      setTrail(res.audit_trail || [])
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to fetch audit trail')
      setTrail([])
    } finally {
      setLoading(false)
    }
  }

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(trail, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit_${incidentId}.json`
    a.click()
  }

  const actionColors: Record<string, string> = {
    LLM_INTERACTION: 'text-purple-400',
    TOOL_CALL: 'text-blue-400',
    ANALYST_ACTION: 'text-green-400',
    STATE_TRANSITION: 'text-yellow-400',
    ALERT_GENERATED: 'text-orange-400',
    LLM_ERROR: 'text-red-400',
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <FileText className="w-6 h-6 text-blue-400" />
        <h1 className="text-2xl font-bold text-white">Audit Trail</h1>
        <span className="text-xs text-soc-muted bg-soc-card border border-soc-border px-2 py-1 rounded-full">
          RBI Compliant
        </span>
      </div>

      {/* Search */}
      <div className="bg-soc-panel border border-soc-border rounded-2xl p-5">
        <div className="flex gap-3">
          <input
            value={incidentId}
            onChange={e => setIncidentId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Enter Incident ID (e.g. INC-A1B2C3D4)"
            className="flex-1 bg-soc-card border border-soc-border rounded-xl px-4 py-2.5 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleSearch}
            disabled={loading}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-5 py-2.5 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
          >
            <Search className="w-4 h-4" />
            Search
          </button>
          {trail.length > 0 && (
            <button
              onClick={exportJSON}
              className="flex items-center gap-2 bg-soc-card hover:bg-soc-border border border-soc-border text-soc-muted hover:text-white px-4 py-2.5 rounded-xl text-sm transition-colors"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
          )}
        </div>
        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
      </div>

      {/* Results */}
      {trail.length > 0 && (
        <div className="bg-soc-panel border border-soc-border rounded-2xl overflow-hidden">
          <div className="px-5 py-4 border-b border-soc-border flex items-center justify-between">
            <h2 className="text-white font-semibold">
              Audit Events for {incidentId}
            </h2>
            <span className="text-soc-muted text-sm">{trail.length} events</span>
          </div>
          <div className="divide-y divide-soc-border font-mono text-xs max-h-[60vh] overflow-auto">
            {trail.map((entry, i) => (
              <div key={i} className="px-5 py-3 hover:bg-soc-card transition-colors">
                <div className="flex items-center gap-3 mb-1">
                  <span className="text-soc-muted">
                    {new Date(entry.timestamp).toLocaleString('en-IN')}
                  </span>
                  <span className={`font-semibold ${actionColors[entry.action] || 'text-soc-muted'}`}>
                    [{entry.action}]
                  </span>
                  {entry.user_id && (
                    <span className="text-soc-muted">by {entry.user_id}</span>
                  )}
                </div>
                {entry.action === 'STATE_TRANSITION' && (
                  <span className="text-yellow-400">
                    {entry.from_state} → {entry.to_state}
                    {entry.reason && <span className="text-soc-muted"> ({entry.reason})</span>}
                  </span>
                )}
                {entry.action === 'TOOL_CALL' && (
                  <div>
                    <span className="text-blue-300">Tool: {entry.tools_called?.[0]}</span>
                    {entry.tool_input && (
                      <span className="text-soc-muted ml-2">Input: {entry.tool_input?.substring(0, 80)}...</span>
                    )}
                  </div>
                )}
                {entry.action === 'ANALYST_ACTION' && (
                  <span className="text-green-300">
                    {entry.analyst_action} — {entry.details}
                  </span>
                )}
                {entry.action === 'LLM_INTERACTION' && (
                  <div className="text-purple-300">
                    Model response logged ({entry.model_response?.length || 0} chars)
                  </div>
                )}
                {entry.action === 'ALERT_GENERATED' && (
                  <span className="text-orange-300">
                    Fidelity: {entry.fidelity_score} | Severity: {entry.severity} | MITRE: {entry.mitre_technique}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {trail.length === 0 && !loading && incidentId && !error && (
        <div className="text-center py-12 text-soc-muted">
          No audit events found for this incident ID
        </div>
      )}
    </div>
  )
}
