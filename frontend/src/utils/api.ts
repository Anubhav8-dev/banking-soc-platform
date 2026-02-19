import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000, // 2min for LLM calls
})

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle 401 globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('soc_token')
      localStorage.removeItem('soc_user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default api

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const loginUser = async (username: string, password: string) => {
  const form = new URLSearchParams()
  form.append('username', username)
  form.append('password', password)
  const res = await api.post('/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })
  return res.data
}

// ─── Data ─────────────────────────────────────────────────────────────────────
export const ingestLogs = async (count = 200) => {
  const res = await api.post('/ingest', { generate_dummy: true, count })
  return res.data
}

export const analyzeLogs = async (timeRange = 60) => {
  const res = await api.post('/analyze', {
    time_range_minutes: timeRange,
    auto_trigger_agent: true,
  })
  return res.data
}

export const getAlerts = async (severity?: string, status?: string) => {
  const params: Record<string, string> = {}
  if (severity) params.severity = severity
  if (status) params.status = status
  const res = await api.get('/alerts', { params })
  return res.data
}

export const getIncident = async (id: string) => {
  const res = await api.get(`/incident/${id}`)
  return res.data
}

export const approveIncident = async (id: string, comment = '', execute = false) => {
  const res = await api.post(`/approve/${id}`, { comment, execute_immediately: execute })
  return res.data
}

export const rejectIncident = async (id: string, comment = '') => {
  const res = await api.post(`/reject/${id}`, { comment })
  return res.data
}

export const getAuditTrail = async (id: string) => {
  const res = await api.get(`/audit/${id}`)
  return res.data
}

export const getHealth = async () => {
  const res = await api.get('/health')
  return res.data
}
