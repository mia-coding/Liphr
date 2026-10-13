import { useEffect, useState } from 'react'

export default function AddPasswordModal({ onSave, onClose }) {
  const [form, setForm] = useState({ website: '', username: '', password: '', notes: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  async function handleSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await onSave(form)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <div className="backdrop" onMouseDown={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="add-title" onMouseDown={(e) => e.stopPropagation()}>
        <h2 id="add-title">Add a password</h2>
        <p className="hint">Everything below is encrypted in your browser before it is saved.</p>
        <form onSubmit={handleSubmit}>
          <label>Website
            <input value={form.website} onChange={set('website')} placeholder="example.com" required autoFocus />
          </label>
          <label>Username
            <input value={form.username} onChange={set('username')} required autoComplete="off" />
          </label>
          <label>Password
            <input type="password" value={form.password} onChange={set('password')} required autoComplete="new-password" />
          </label>
          <label>Notes
            <textarea value={form.notes} onChange={set('notes')} rows={3} />
          </label>
          {error && <p className="msg error" role="alert">{error}</p>}
          <div className="modal-actions">
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn" disabled={busy}>{busy ? 'Encrypting…' : 'Save password'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}
