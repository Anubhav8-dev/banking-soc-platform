import React, { createContext, useContext, useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import DashboardLayout from './pages/DashboardLayout'
import AlertsPage from './pages/AlertsPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import AuditPage from './pages/AuditPage'
import SettingsPage from './pages/SettingsPage'

// ─── Auth Context ─────────────────────────────────────────────────────────────
interface AuthUser {
  username: string
  role: string
  token: string
}

interface AuthContextType {
  user: AuthUser | null
  login: (user: AuthUser) => void
  logout: () => void
}

export const AuthContext = createContext<AuthContextType>({
  user: null,
  login: () => {},
  logout: () => {},
})

export const useAuth = () => useContext(AuthContext)

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  return user ? <>{children}</> : <Navigate to="/login" />
}

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(() => {
    try {
      const stored = localStorage.getItem('soc_user')
      return stored ? JSON.parse(stored) : null
    } catch {
      return null
    }
  })

  const login = (u: AuthUser) => {
    setUser(u)
    localStorage.setItem('soc_user', JSON.stringify(u))
    localStorage.setItem('soc_token', u.token)
  }

  const logout = () => {
    setUser(null)
    localStorage.removeItem('soc_user')
    localStorage.removeItem('soc_token')
  }

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <DashboardLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/alerts" />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="incident/:id" element={<IncidentDetailPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </AuthContext.Provider>
  )
}
