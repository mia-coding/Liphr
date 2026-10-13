import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase.js'
import { useAuth } from '../context/AuthContext.jsx'
import { deriveKey, encrypt, decrypt } from '../lib/crypto.js'
import AddPasswordModal from '../components/AddPasswordModal.jsx'

const MAX_PASSWORDS = 100

export default function Vault() {
  const { user } = useAuth()
  const [rows, setRows] = useState(null)       // encrypted rows exactly as stored in Supabase
  const [key, setKey] = useState(null)         // derived encryption key, kept in memory only
  const [items, setItems] = useState([])       // decrypted website + username for the table
  const [revealed, setRevealed] = useState({}) // id -> { password, notes } once decrypted on request
  const [master, setMaster] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [showAdd, setShowAdd] = useState(false)

  useEffect(() => {
    supabase
      .from('passwords')
      .select('*')
      .order('created_at', { ascending: true })
      .then(({ data, error }) => (error ? setError(error.message) : setRows(data)))
  }, [])

  const firstTime = rows && rows.length === 0

  async function unlock(e) {
    e.preventDefault()
    setError('')
    if (firstTime) {
      if (master.length < 10) return setError('Use at least 10 characters for your master password.')
      if (master !== confirm) return setError("The two master passwords don't match.")
    }
    setBusy(true)
    const k = await deriveKey(master, user.id)
    try {
      // Decrypting existing rows doubles as a check that the master password is right.
      const decrypted = await Promise.all(
        rows.map(async (r) => ({
          id: r.id,
          website: await decrypt(k, r.website_enc, 'website'),
          username: await decrypt(k, r.username_enc, 'username'),
        }))
      )
      setItems(decrypted)
      setKey(k)
    } catch {
      setError('That master password is wrong. Try again.')
    }
    setBusy(false)
  }

  async function toggleReveal(id) {
    if (revealed[id]) {
      const { [id]: _removed, ...rest } = revealed
      return setRevealed(rest)
    }
    const row = rows.find((r) => r.id === id)
    const password = await decrypt(key, row.password_enc, 'password')
    const notes = row.notes_enc ? await decrypt(key, row.notes_enc, 'notes') : ''
    setRevealed({ ...revealed, [id]: { password, notes } })
  }

  async function copyPassword(id) {
    const row = rows.find((r) => r.id === id)
    await navigator.clipboard.writeText(await decrypt(key, row.password_enc, 'password'))
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 20000) // clear after 20s
  }

  async function addPassword(form) {
    const payload = {
      website_enc: await encrypt(key, form.website, 'website'),
      username_enc: await encrypt(key, form.username, 'username'),
      password_enc: await encrypt(key, form.password, 'password'),
      notes_enc: form.notes ? await encrypt(key, form.notes, 'notes') : null,
    }
    const { data, error } = await supabase.from('passwords').insert(payload).select().single()
    if (error) throw new Error(error.message)
    setRows([...rows, data])
    setItems([...items, { id: data.id, website: form.website, username: form.username }])
    setShowAdd(false)
  }

  async function removePassword(id) {
    if (!window.confirm('Delete this password? This cannot be undone.')) return
    const { error } = await supabase.from('passwords').delete().eq('id', id)
    if (error) return setError(error.message)
    setRows(rows.filter((r) => r.id !== id))
    setItems(items.filter((i) => i.id !== id))
  }

  if (!rows) return <p className="page-note">{error || 'Loading your vault…'}</p>

  if (!key) {
    return (
      <main className="page">
        <form className="unlock" onSubmit={unlock}>
          <h1>{firstTime ? 'Create your master password' : 'Unlock your vault'}</h1>
          <p className="hint">
            {firstTime
              ? 'This password encrypts everything you save. We never see it and can’t reset it, so store it somewhere safe.'
              : 'Enter your master password to decrypt your entries in this browser.'}
          </p>
          <label>Master password
            <input type="password" value={master} onChange={(e) => setMaster(e.target.value)} required autoFocus autoComplete="off" />
          </label>
          {firstTime && (
            <label>Confirm master password
              <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="off" />
            </label>
          )}
          {error && <p className="msg error" role="alert">{error}</p>}
          <button className="btn" disabled={busy}>{busy ? 'Unlocking…' : firstTime ? 'Create and unlock' : 'Unlock'}</button>
        </form>
      </main>
    )
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>My vault</h1>
        <p className="count">{items.length} of {MAX_PASSWORDS} passwords</p>
      </div>
      {error && <p className="msg error" role="alert">{error}</p>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Website</th><th>Username</th><th>Password</th><th>Notes</th><th><span className="sr-only">Actions</span></th></tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={5} className="empty">No passwords yet. Add your first one below.</td></tr>
            )}
            {items.map((item) => {
              const r = revealed[item.id]
              return (
                <tr key={item.id}>
                  <td>{item.website}</td>
                  <td>{item.username}</td>
                  <td className="secret">{r ? r.password : '••••••••'}</td>
                  <td>{r ? r.notes || '—' : '—'}</td>
                  <td className="row-actions">
                    <button className="link-btn" onClick={() => toggleReveal(item.id)}>{r ? 'Hide' : 'Reveal'}</button>
                    <button className="link-btn" onClick={() => copyPassword(item.id)}>Copy</button>
                    <button className="link-btn danger" onClick={() => removePassword(item.id)}>Delete</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <button className="btn add" onClick={() => setShowAdd(true)} disabled={items.length >= MAX_PASSWORDS}>
        Add new password
      </button>
      {items.length >= MAX_PASSWORDS && <p className="hint">You’ve reached the 100 password limit. Delete one to add another.</p>}

      {showAdd && <AddPasswordModal onSave={addPassword} onClose={() => setShowAdd(false)} />}
    </main>
  )
}
