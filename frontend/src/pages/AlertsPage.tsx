import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, RefreshCw, Database, Cpu, ChevronRight,
  Clock, Zap, Filter, TrendingUp
} from 'lucide-react'
import { getAlerts, ingestLogs, analyzeLogs } from '../utils/api'
import { useAuth } from '../App'

const severityConfig: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  Critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', dot: 'bg-red-400' },
  High:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', dot: 'bg-orange-400' },
  Medium:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', dot: 'bg-yellow-400' },
  Low:      { color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30', dot: 'bg-green-400' },
}

const statusConfig: Record<string, string> = {
  pending_approval: 'text-yellow-400',
  approved: 'text-green-400',
  rejected: 'text-red-400',
  remediation_in_progress: 'text-blue-400',
}

export default function AlertsPage() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [incidents, setIncidents] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [ingesting, setIngesting] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [filterSeverity, setFilterSeverity] = useState('')
  const [log, setLog] = useState<string[]>([])

  const addLog = (msg: string) => setLog(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev.slice(0, 19)])

  const fetchAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getAlerts(filterSeverity || undefined)
      setIncidents(data.incidents || [])
    } catch (e: any) {
      addLog(`Error fetching alerts: ${e.message}`)
    } finally {
      setLoading(false)
    }
  }, [filterSeverity])

  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  const handleIngest = async () => {
    setIngesting(true)
    addLog('Generating synthetic brute-force attack logs (200 events)...')
    try {
      const res = await ingestLogs(200)
      addLog(`✓ Ingested ${res.result.success} events | MITRE: ${res.result.mitre_technique}`)
    } catch (e: any) {
      addLog(`✗ Ingestion failed: ${e.message}`)
    } finally {
      setIngesting(false)
    }
  }

  const handleAnalyze = async () => {
    setAnalyzing(true)
    addLog('Running UEBA analytics + fidelity scoring...')
    try {
      const res = await analyzeLogs(60)
      if (res.agent_triggered) {
        addLog(`✓ Agent triggered! Incident: ${res.agent_result?.incident_id} | Fidelity: ${res.fidelity_score?.toFixed(3)}`)
      } else {
        addLog(`Analysis complete | Fidelity: ${res.fidelity_score?.toFixed(3)} (below threshold)`)
      }
      fetchAlerts()
    } catch (e: any) {
      addLog(`✗ Analysis failed: ${e.message}`)
    } finally {
      setAnalyzing(false)
    }
  }

  // Stats
  const critical = incidents.filter(i => i.severity === 'Critical').length
  const high = incidents.filter(i => i.severity === 'High').length
  const pending = incidents.filter(i => i.status === 'pending_approval').length
  const avgFidelity = incidents.length
    ? (incidents.reduce((s, i) => s + (i.fidelity_score || 0), 0) / incidents.length).toFixed(3)
    : '0.000'

  return (
    <div className="p-6 space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Critical" value={critical} color="text-red-400" icon={AlertTriangle} />
        <StatCard label="High" value={high} color="text-orange-400" icon={TrendingUp} />
        <StatCard label="Pending Approval" value={pending} color="text-yellow-400" icon={Clock} />
        <StatCard label="Avg Fidelity" value={avgFidelity} color="text-blue-400" icon={Zap} />
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleIngest}
          disabled={ingesting}
          className="flex items-center gap-2 bg-soc-card hover:bg-soc-border border border-soc-border px-4 py-2 rounded-lg text-sm text-white transition-colors disabled:opacity-50"
        >
          <Database className="w-4 h-4 text-green-400" />
          {ingesting ? 'Ingesting...' : 'Generate Test Logs'}
        </button>

        <button
          onClick={handleAnalyze}
          disabled={analyzing}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded-lg text-sm text-white transition-colors disabled:opacity-50"
        >
          <Cpu className="w-4 h-4" />
          {analyzing ? 'Analyzing...' : 'Run UEBA Analysis'}
        </button>

        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="flex items-center gap-2 bg-soc-card hover:bg-soc-border border border-soc-border px-4 py-2 rounded-lg text-sm text-soc-muted hover:text-white transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>

        {/* Severity filter */}
        <div className="flex items-center gap-2 ml-auto">
          <Filter className="w-4 h-4 text-soc-muted" />
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Incident List */}
        <div className="xl:col-span-2">
          <div className="bg-soc-panel border border-soc-border rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-soc-border flex items-center justify-between">
              <h2 className="text-white font-semibold">Active Incidents</h2>
              <span className="text-soc-muted text-sm">{incidents.length} total</span>
            </div>

            {incidents.length === 0 ? (
              <div className="p-12 text-center">
                <AlertTriangle className="w-12 h-12 text-soc-border mx-auto mb-3" />
                <p className="text-soc-muted">No incidents. Generate test logs and run analysis.</p>
              </div>
            ) : (
              <div className="divide-y divide-soc-border">
                {incidents.map((incident) => {
                  const sev = severityConfig[incident.severity] || severityConfig.Low
                  const statusColor = statusConfig[incident.status] || 'text-soc-muted'
                  return (
                    <button
                      key={incident.incident_id}
                      onClick={() => navigate(`/incident/${incident.incident_id}`)}
                      className="w-full text-left px-5 py-4 hover:bg-soc-card transition-colors group"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-start gap-3 flex-1 min-w-0">
                          <span className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${sev.dot}`} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="text-white font-medium text-sm font-mono">
                                {incident.incident_id}
                              </span>
                              <span className={`text-xs px-2 py-0.5 rounded-full border ${sev.bg} ${sev.color} ${sev.border}`}>
                                {incident.severity}
                              </span>
                              <span className={`text-xs ${statusColor}`}>
                                {incident.status?.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <div className="text-soc-muted text-xs font-mono truncate">
                              {incident.agent_response?.summary?.substring(0, 100) || 'No summary available'}...
                            </div>
                            <div className="flex items-center gap-4 mt-2">
                              <span className="text-xs text-soc-muted">
                                {incident.agent_response?.mitre_technique || '—'}
                              </span>
                              <span className="text-xs text-soc-muted">
                                {incident.logs_analyzed} events analyzed
                              </span>
                              <span className="text-xs text-soc-muted">
                                {new Date(incident.created_at).toLocaleTimeString('en-IN')}
                              </span>
                            </div>
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <div className="text-lg font-bold font-mono text-white">
                            {(incident.fidelity_score * 100).toFixed(0)}%
                          </div>
                          <div className="text-xs text-soc-muted">Fidelity</div>
                          <ChevronRight className="w-4 h-4 text-soc-muted mt-1 ml-auto group-hover:text-white transition-colors" />
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Activity Log */}
        <div>
          <div className="bg-soc-panel border border-soc-border rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-soc-border">
              <h2 className="text-white font-semibold">Activity Log</h2>
            </div>
            <div className="p-4 space-y-2 max-h-96 overflow-auto font-mono">
              {log.length === 0 ? (
                <p className="text-soc-muted text-xs">No activity yet...</p>
              ) : (
                log.map((entry, i) => (
                  <div key={i} className="text-xs text-green-400/80 leading-relaxed">{entry}</div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color, icon: Icon }: any) {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-soc-muted text-xs uppercase tracking-wider">{label}</span>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <span className={`text-2xl font-bold font-mono ${color}`}>{value}</span>
    </div>
  )
}
