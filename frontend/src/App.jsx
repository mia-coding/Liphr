import { useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import AuthModal from './components/AuthModal.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import Landing from './pages/Landing.jsx'
import Vault from './pages/Vault.jsx'

export default function App() {
  // null | 'login' | 'signup'
  const [authMode, setAuthMode] = useState(null)

  return (
    <>
      <Navbar onOpenAuth={setAuthMode} />
      <Routes>
        <Route path="/" element={<Landing onOpenAuth={setAuthMode} />} />
        <Route
          path="/vault"
          element={
            <ProtectedRoute>
              <Vault />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      {authMode && (
        <AuthModal mode={authMode} onModeChange={setAuthMode} onClose={() => setAuthMode(null)} />
      )}
    </>
  )
}
