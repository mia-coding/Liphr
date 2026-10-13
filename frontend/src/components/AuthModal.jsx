import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function AuthModal({ mode, onModeChange, onClose }) {
  const { signIn, signUp } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const isLogin = mode === 'login'

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setNotice('')
    setBusy(true)
    const { data, error } = isLogin ? await signIn(email, password) : await signUp(email, password)
    setBusy(false)
    if (error) return setError(error.message)
    if (data.session) {
      onClose()
      navigate('/vault')
    } else {
      setNotice('Check your email to confirm your account, then log in.')
    }
  }

  return (
    <div className="backdrop" onMouseDown={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="auth-title" onMouseDown={(e) => e.stopPropagation()}>
        <h2 id="auth-title">{isLogin ? 'Log in' : 'Create your account'}</h2>
        <form onSubmit={handleSubmit}>
          <label>Email
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus autoComplete="email" />
          </label>
          <label>Account password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8}
              autoComplete={isLogin ? 'current-password' : 'new-password'} />
          </label>
          {error && <p className="msg error" role="alert">{error}</p>}
          {notice && <p className="msg ok">{notice}</p>}
          <div className="modal-actions">
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn" disabled={busy}>{busy ? 'Working…' : isLogin ? 'Log in' : 'Sign up'}</button>
          </div>
        </form>
        <p className="switch">
          {isLogin ? 'New here?' : 'Already have an account?'}{' '}
          <button className="link-btn" onClick={() => onModeChange(isLogin ? 'signup' : 'login')}>
            {isLogin ? 'Sign up' : 'Log in'}
          </button>
        </p>
      </div>
    </div>
  )
}
