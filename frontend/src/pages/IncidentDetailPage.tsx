import React, { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, CheckCircle, XCircle, AlertOctagon, Shield, Info, Clock } from 'lucide-react'
import { Chart as ChartJS, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js'
import { Bar } from 'react-chartjs-2'
import { getIncident, approveIncident, rejectIncident } from '../utils/api'
import { useAuth } from '../App'

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend)

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [comment, setComment] = useState('')
  const [message, setMessage] = useState('')

  const fetch = async () => {
    if (!id) return
    setLoading(true)
    try {
      const res = await getIncident(id)
      setData(res)
    } catch (e: any) {
      setMessage('Failed to load incident: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetch() }, [id])

  const handleApprove = async () => {
    if (!id) return
    setActionLoading(true)
    try {
      await approveIncident(id, comment)
      setMessage('✓ Playbook approved successfully')
      fetch()
    } catch (e: any) {
      setMessage('Error: ' + (e.response?.data?.detail || e.message))
    } finally {
      setActionLoading(false)
    }
  }

  const handleReject = async () => {
    if (!id) return
    if (!comment) { setMessage('Please provide a rejection reason'); return }
    setActionLoading(true)
    try {
      await rejectIncident(id, comment)
      setMessage('Playbook rejected')
      fetch()
    } catch (e: any) {
      setMessage('Error: ' + (e.response?.data?.detail || e.message))
    } finally {
      setActionLoading(false)
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-full text-soc-muted">
      Loading incident data...
    </div>
  )

  const incident = data?.incident
  const response = incident?.agent_response
  const analysis = incident?.analysis
  const auditTrail = data?.audit_trail || []
  const topFeatures = analysis?.top_contributing_features || []

  const isSupervisor = user?.role === 'supervisor'
  const isPending = incident?.status === 'pending_approval'

  // SHAP chart data
  const shapChartData = {
    labels: topFeatures.map((f: any) => f.feature.replace(/_/g, ' ')),
    datasets: [{
      label: 'Feature Importance (SHAP)',
      data: topFeatures.map((f: any) => Math.abs(f.importance)),
      backgroundColor: topFeatures.map((_: any, i: number) =>
        i === 0 ? 'rgba(239,68,68,0.7)' : i === 1 ? 'rgba(249,115,22,0.7)' : 'rgba(234,179,8,0.7)'
      ),
      borderColor: topFeatures.map((_: any, i: number) =>
        i === 0 ? '#ef4444' : i === 1 ? '#f97316' : '#eab308'
      ),
      borderWidth: 1,
      borderRadius: 4,
    }]
  }

  const chartOptions = {
    indexAxis: 'y' as const,
    responsive: true,
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor: '#141d35', titleColor: '#e2e8f0', bodyColor: '#94a3b8' }
    },
    scales: {
      x: { grid: { color: '#1e2d4f' }, ticks: { color: '#64748b' } },
      y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11 } } }
    }
  }

  const sevColors: Record<string, string> = {
    Critical: 'text-red-400 border-red-500/30 bg-red-500/10',
    High: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
    Medium: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
    Low: 'text-green-400 border-green-500/30 bg-green-500/10',
  }
  const sevClass = sevColors[incident?.severity] || sevColors.Low

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Top bar */}
      <div className="bg-soc-panel border-b border-soc-border px-6 py-4 flex items-center gap-4">
        <button onClick={() => navigate('/alerts')} className="text-soc-muted hover:text-white">
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-3 flex-1">
          <h1 className="text-white font-bold font-mono text-lg">{id}</h1>
          <span className={`text-xs px-2.5 py-1 rounded-full border ${sevClass}`}>
            {incident?.severity}
          </span>
          <span className="text-soc-muted text-sm capitalize">
            {incident?.status?.replace(/_/g, ' ')}
          </span>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold font-mono text-white">
            {((incident?.fidelity_score || 0) * 100).toFixed(0)}%
          </div>
          <div className="text-xs text-soc-muted">Fidelity</div>
        </div>
      </div>

      {message && (
        <div className="mx-6 mt-4 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400 text-sm">
          {message}
        </div>
      )}

      {/* Split Screen */}
      <div className="flex-1 overflow-hidden grid grid-cols-1 xl:grid-cols-2">
        {/* ── Left: Evidence ─────────────────────────────────────────── */}
        <div className="overflow-auto border-r border-soc-border p-6 space-y-5">
          {/* Anomaly Explanation Chart */}
          <Section title="SHAP Anomaly Explanation" icon={Info}>
            {topFeatures.length > 0 ? (
              <div className="bg-soc-card rounded-xl p-4">
                <Bar data={shapChartData} options={chartOptions} height={120} />
                <div className="mt-3 space-y-2">
                  {topFeatures.map((f: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-soc-muted font-mono">{f.feature}</span>
                      <div className="flex items-center gap-3">
                        <span className="text-soc-muted">val: {f.actual_value?.toFixed(3)}</span>
                        <span className="text-orange-400 font-mono">SHAP: {f.shap_value?.toFixed(4)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-soc-muted text-sm">No SHAP data available</p>
            )}
          </Section>

          {/* MITRE Mapping */}
          <Section title="MITRE ATT&CK Mapping" icon={Shield}>
            <div className="grid grid-cols-2 gap-3">
              <InfoBox label="Technique" value={response?.mitre_technique || '—'} mono />
              <InfoBox label="Tactic" value={response?.mitre_tactic || '—'} />
              <InfoBox label="Confidence" value={`${((response?.confidence_score || 0) * 100).toFixed(0)}%`} />
              <InfoBox label="Severity" value={incident?.severity || '—'} />
            </div>
          </Section>

          {/* Key Findings */}
          <Section title="Key Findings" icon={AlertOctagon}>
            <div className="space-y-2">
              {(response?.explanation || ['No findings']).map((exp: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <span className="text-blue-400 flex-shrink-0 mt-0.5">›</span>
                  <span className="text-soc-muted">{exp}</span>
                </div>
              ))}
            </div>
          </Section>

          {/* Audit Trail */}
          <Section title="Audit Trail" icon={Clock}>
            <div className="space-y-2 max-h-64 overflow-auto font-mono text-xs">
              {auditTrail.slice(0, 20).map((entry: any, i: number) => (
                <div key={i} className="flex items-start gap-2 py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted flex-shrink-0">
                    {new Date(entry.timestamp).toLocaleTimeString('en-IN')}
                  </span>
                  <span className="text-blue-400 flex-shrink-0">[{entry.action}]</span>
                  <span className="text-soc-muted">
                    {entry.analyst_action || entry.tool_input || entry.from_state + '→' + entry.to_state || ''}
                  </span>
                </div>
              ))}
              {auditTrail.length === 0 && (
                <p className="text-soc-muted">No audit entries yet</p>
              )}
            </div>
          </Section>
        </div>

        {/* ── Right: Playbook ─────────────────────────────────────────── */}
        <div className="overflow-auto p-6 space-y-5">
          {/* Summary */}
          <Section title="AI-Generated Summary" icon={Info}>
            <p className="text-soc-muted text-sm leading-relaxed">
              {response?.summary || 'No summary available'}
            </p>
          </Section>

          {/* Playbook Steps */}
          <Section title="Incident Response Playbook" icon={CheckCircle}>
            <div className="space-y-3">
              {(response?.playbook_steps || []).map((step: any, i: number) => (
                <div key={i} className="bg-soc-card border border-soc-border rounded-xl p-4">
                  <div className="flex items-start gap-3">
                    <span className="w-7 h-7 rounded-full bg-blue-600/20 border border-blue-500/30 text-blue-400 text-xs font-bold flex items-center justify-center flex-shrink-0">
                      {step.step_number || i + 1}
                    </span>
                    <div className="flex-1">
                      <p className="text-white text-sm">{step.action}</p>
                      <div className="flex items-center gap-3 mt-1.5">
                        <span className="text-xs text-soc-muted">Team: {step.responsible_team}</span>
                        <span className="text-xs text-orange-400">⏱ {step.deadline}</span>
                        {step.compliance_ref && (
                          <span className="text-xs text-blue-400">{step.compliance_ref}</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* Recommended Actions */}
          <Section title="Recommended Actions" icon={Zap}>
            <div className="space-y-2">
              {(response?.recommended_actions || []).map((action: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm py-2 border-b border-soc-border/30 last:border-0">
                  <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                  <span className="text-soc-muted">{action}</span>
                </div>
              ))}
            </div>
          </Section>

          {/* Regulatory Obligations */}
          {response?.regulatory_obligations?.length > 0 && (
            <Section title="Regulatory Obligations" icon={AlertOctagon}>
              <div className="space-y-2">
                {response.regulatory_obligations.map((obs: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 bg-red-500/5 border border-red-500/20 rounded-lg px-3 py-2">
                    <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0" />
                    <span className="text-sm text-red-300">{obs}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Action Buttons */}
          {isPending && (
            <div className="bg-soc-panel border border-soc-border rounded-2xl p-5 space-y-3">
              <h3 className="text-white font-semibold text-sm">Analyst Decision</h3>
              <textarea
                value={comment}
                onChange={e => setComment(e.target.value)}
                placeholder="Add a comment or reason..."
                className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm text-white resize-none h-20 focus:outline-none focus:border-blue-500"
              />
              <div className="flex gap-3">
                {isSupervisor && (
                  <button
                    onClick={handleApprove}
                    disabled={actionLoading}
                    className="flex-1 flex items-center justify-center gap-2 bg-green-600 hover:bg-green-500 text-white py-2.5 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Approve Playbook
                  </button>
                )}
                <button
                  onClick={handleReject}
                  disabled={actionLoading}
                  className="flex-1 flex items-center justify-center gap-2 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 text-red-400 py-2.5 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                >
                  <XCircle className="w-4 h-4" />
                  Reject
                </button>
                {!isSupervisor && (
                  <p className="text-xs text-soc-muted text-center w-full mt-1">
                    Approval requires Supervisor role
                  </p>
                )}
              </div>
            </div>
          )}

          {!isPending && (
            <div className="bg-soc-card border border-soc-border rounded-xl p-4 text-center">
              <p className="text-soc-muted text-sm capitalize">
                Status: {incident?.status?.replace(/_/g, ' ')} by {incident?.approved_by || incident?.rejected_by || 'system'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-2xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-blue-400" />
        <h3 className="text-white font-semibold text-sm">{title}</h3>
      </div>
      {children}
    </div>
  )
}

function InfoBox({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="bg-soc-card border border-soc-border rounded-xl p-3">
      <p className="text-xs text-soc-muted mb-1">{label}</p>
      <p className={`text-white text-sm font-semibold ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  )
}

function Zap({ className }: { className: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  )
}
