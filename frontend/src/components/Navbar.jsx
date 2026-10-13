import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Navbar({ onOpenAuth }) {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()

  async function handleSignOut() {
    await signOut()
    navigate('/')
  }

  return (
    <header className="nav">
      <Link to="/" className="brand">Liphr</Link>
      <nav className="nav-links" aria-label="Account">
        {user ? (
          <>
            <Link to="/vault">My vault</Link>
            <button className="link-btn" onClick={handleSignOut}>Log out</button>
          </>
        ) : (
          <>
            <button className="link-btn" onClick={() => onOpenAuth('login')}>Log in</button>
            <button className="link-btn" onClick={() => onOpenAuth('signup')}>Sign up</button>
          </>
        )}
      </nav>
    </header>
  )
}
