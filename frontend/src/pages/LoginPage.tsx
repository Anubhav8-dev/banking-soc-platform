import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, AlertTriangle } from 'lucide-react'
import { loginUser } from '../utils/api'
import { useAuth } from '../App'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const data = await loginUser(username, password)
      login({ username: data.username, role: data.role, token: data.access_token })
      navigate('/alerts')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-soc-bg flex items-center justify-center relative overflow-hidden">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage: 'linear-gradient(rgba(30,136,229,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(30,136,229,0.3) 1px, transparent 1px)',
          backgroundSize: '50px 50px',
        }}
      />

      <div className="relative z-10 w-full max-w-md px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <div className="p-3 bg-blue-600/20 rounded-2xl border border-blue-500/30 glow-accent">
              <Shield className="w-10 h-10 text-blue-400" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">BankShield SOC</h1>
          <p className="text-soc-muted mt-2 text-sm">Autonomous Cyber Incident Response Platform</p>
          <div className="flex items-center justify-center gap-2 mt-3">
            <span className="w-2 h-2 rounded-full bg-green-400 pulse-dot" />
            <span className="text-xs text-green-400 font-mono">OFFLINE SECURE MODE</span>
          </div>
        </div>

        {/* Login Card */}
        <div className="bg-soc-panel border border-soc-border rounded-2xl p-8 glow-accent">
          <h2 className="text-lg font-semibold text-white mb-6">Secure Authentication</h2>

          {error && (
            <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span className="text-red-400 text-sm">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-soc-muted mb-1.5 uppercase tracking-wider">Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="w-full bg-soc-card border border-soc-border rounded-lg px-4 py-3 text-white text-sm focus:outline-none focus:border-blue-500 transition-colors font-mono"
                placeholder="analyst1"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-soc-muted mb-1.5 uppercase tracking-wider">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full bg-soc-card border border-soc-border rounded-lg px-4 py-3 text-white text-sm focus:outline-none focus:border-blue-500 transition-colors font-mono pr-12"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-soc-muted hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-colors mt-2"
            >
              {loading ? 'Authenticating...' : 'Access SOC Platform'}
            </button>
          </form>

          {/* Demo credentials */}
          <div className="mt-6 p-4 bg-soc-bg rounded-lg border border-soc-border">
            <p className="text-xs text-soc-muted mb-2">Demo Credentials:</p>
            <div className="space-y-1 text-xs font-mono">
              <div className="text-green-400">analyst1 / analyst123 <span className="text-soc-muted">(Analyst)</span></div>
              <div className="text-orange-400">supervisor1 / supervisor123 <span className="text-soc-muted">(Supervisor)</span></div>
              <div className="text-blue-400">auditor1 / auditor123 <span className="text-soc-muted">(Auditor)</span></div>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-soc-muted mt-4">
          All data stays local · No telemetry · RBI Compliant
        </p>
      </div>
    </div>
  )
}
