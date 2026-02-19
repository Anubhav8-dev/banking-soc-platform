import React, { useState, useEffect } from 'react'
import { Settings, Server, Shield, Activity } from 'lucide-react'
import { getHealth } from '../utils/api'

export default function SettingsPage() {
  const [health, setHealth] = useState<any>(null)

  useEffect(() => {
    getHealth().then(setHealth).catch(() => {})
  }, [])

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Settings className="w-6 h-6 text-blue-400" />
        <h1 className="text-2xl font-bold text-white">System Settings</h1>
      </div>

      {/* System Health */}
      <div className="bg-soc-panel border border-soc-border rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-5">
          <Activity className="w-5 h-5 text-blue-400" />
          <h2 className="text-white font-semibold">System Health</h2>
        </div>
        {health ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(health.checks || {}).map(([key, val]: [string, any]) => (
              <div key={key} className="bg-soc-card border border-soc-border rounded-xl p-4">
                <p className="text-xs text-soc-muted mb-2 capitalize">{key.replace(/_/g, ' ')}</p>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${val === 'ok' || val === 'disabled' ? (val === 'ok' ? 'bg-green-400' : 'bg-blue-400') : 'bg-red-400'}`} />
                  <span className={`text-sm font-mono ${val === 'ok' ? 'text-green-400' : val === 'disabled' ? 'text-blue-400' : 'text-red-400'}`}>
                    {String(val)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-soc-muted">Loading health data...</p>
        )}
      </div>

      {/* Security Settings */}
      <div className="bg-soc-panel border border-soc-border rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-5">
          <Shield className="w-5 h-5 text-blue-400" />
          <h2 className="text-white font-semibold">Security Configuration</h2>
        </div>
        <div className="space-y-3">
          {[
            { label: 'Internet Access', value: 'Disabled (Offline Mode)', color: 'text-red-400' },
            { label: 'Telemetry', value: 'Disabled', color: 'text-red-400' },
            { label: 'LLM Provider', value: 'Ollama (Local — llama3)', color: 'text-green-400' },
            { label: 'Data Encryption', value: 'AES-256 at rest', color: 'text-green-400' },
            { label: 'JWT Expiry', value: '8 hours', color: 'text-blue-400' },
            { label: 'Dedup Window', value: '5 minutes', color: 'text-blue-400' },
            { label: 'Fidelity Threshold', value: '0.75 (agent trigger)', color: 'text-yellow-400' },
            { label: 'Compliance Framework', value: 'RBI + CERT-In + MITRE ATT&CK', color: 'text-green-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="flex items-center justify-between py-2 border-b border-soc-border/50 last:border-0">
              <span className="text-soc-muted text-sm">{label}</span>
              <span className={`text-sm font-mono ${color}`}>{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Role Permissions */}
      <div className="bg-soc-panel border border-soc-border rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-5">
          <Server className="w-5 h-5 text-blue-400" />
          <h2 className="text-white font-semibold">RBAC Permissions</h2>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted">
                <th className="text-left py-2 pr-6">Permission</th>
                <th className="text-center py-2 px-4">Analyst</th>
                <th className="text-center py-2 px-4">Supervisor</th>
                <th className="text-center py-2 px-4">Auditor</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/50">
              {[
                ['View Alerts', true, true, true],
                ['Run Analysis', true, true, false],
                ['Ingest Logs', true, true, false],
                ['Approve Playbook', false, true, false],
                ['Reject Playbook', true, true, false],
                ['View Audit Trail', false, true, true],
                ['Execute Remediation', false, true, false],
              ].map(([perm, analyst, supervisor, auditor]) => (
                <tr key={String(perm)} className="text-soc-muted">
                  <td className="py-2 pr-6 text-white">{perm}</td>
                  <td className="text-center py-2 px-4">{analyst ? '✓' : '✗'}</td>
                  <td className="text-center py-2 px-4">{supervisor ? '✓' : '✗'}</td>
                  <td className="text-center py-2 px-4">{auditor ? '✓' : '✗'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
