import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <p className="page-note">Checking your session…</p>
  if (!user) return <Navigate to="/" replace />
  return children
}
