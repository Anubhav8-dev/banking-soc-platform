import React, { useState, useEffect } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, FileText, Settings, LogOut,
  Activity, Bell, ChevronRight, Wifi, WifiOff
} from 'lucide-react'
import { useAuth } from '../App'
import { getHealth } from '../utils/api'

const navItems = [
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/audit', icon: FileText, label: 'Audit Trail' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

const roleColors: Record<string, string> = {
  analyst: 'text-green-400',
  supervisor: 'text-orange-400',
  auditor: 'text-blue-400',
}

export default function DashboardLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [health, setHealth] = useState<any>(null)
  const [time, setTime] = useState(new Date())

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000)
    getHealth().then(setHealth).catch(() => {})
    return () => clearInterval(interval)
  }, [])

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const esOk = health?.checks?.elasticsearch === 'ok'
  const ollamaOk = health?.checks?.ollama === 'ok'

  return (
    <div className="flex h-screen bg-soc-bg overflow-hidden">
      {/* ── Sidebar ─────────────────────────────────────────────────── */}
      <aside className="w-64 bg-soc-panel border-r border-soc-border flex flex-col">
        {/* Logo */}
        <div className="p-5 border-b border-soc-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600/20 rounded-xl border border-blue-500/30">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h1 className="text-white font-bold text-sm">BankShield SOC</h1>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 pulse-dot" />
                <span className="text-xs text-green-400">OFFLINE SECURE</span>
              </div>
            </div>
          </div>
        </div>

        {/* System Status */}
        <div className="p-4 border-b border-soc-border">
          <p className="text-xs text-soc-muted uppercase tracking-wider mb-2">System Status</p>
          <div className="space-y-1.5">
            <StatusRow label="Elasticsearch" ok={esOk} />
            <StatusRow label="Ollama LLM" ok={ollamaOk} />
            <StatusRow label="Internet" ok={false} label2="Disabled" />
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map(({ path, icon: Icon, label }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                    : 'text-soc-muted hover:text-white hover:bg-soc-card'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
              <ChevronRight className="w-3 h-3 ml-auto opacity-50" />
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="p-4 border-t border-soc-border">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-full bg-blue-600/30 border border-blue-500/30 flex items-center justify-center">
              <span className="text-blue-400 text-xs font-bold">
                {user?.username?.[0]?.toUpperCase()}
              </span>
            </div>
            <div>
              <p className="text-white text-sm font-medium">{user?.username}</p>
              <p className={`text-xs capitalize ${roleColors[user?.role || ''] || 'text-soc-muted'}`}>
                {user?.role}
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 text-soc-muted hover:text-red-400 text-sm rounded-lg hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── Main Content ─────────────────────────────────────────────── */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-14 bg-soc-panel border-b border-soc-border flex items-center justify-between px-6">
          <div className="flex items-center gap-2 text-soc-muted text-sm">
            <Activity className="w-4 h-4 text-blue-400" />
            <span>Security Operations Center</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-soc-muted text-xs font-mono">
              {time.toLocaleTimeString('en-IN', { hour12: false })} IST
            </span>
            <div className="text-xs text-soc-muted font-mono">
              {time.toLocaleDateString('en-IN')}
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="flex-1 overflow-auto">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

function StatusRow({ label, ok, label2 }: { label: string; ok: boolean | undefined; label2?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-soc-muted">{label}</span>
      <div className="flex items-center gap-1.5">
        <span className={`w-1.5 h-1.5 rounded-full ${ok === false ? 'bg-red-400' : ok ? 'bg-green-400' : 'bg-yellow-400'}`} />
        <span className={`text-xs ${ok === false ? 'text-red-400' : ok ? 'text-green-400' : 'text-yellow-400'}`}>
          {label2 || (ok === false ? 'Offline' : ok ? 'Online' : '?')}
        </span>
      </div>
    </div>
  )
}
