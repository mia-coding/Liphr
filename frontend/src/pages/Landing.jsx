import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Landing({ onOpenAuth }) {
  const { user } = useAuth()
  return (
    <main className="landing">
      <section className="hero">
        <div className="hero-copy">
          <h1>Your passwords, locked before they leave your browser.</h1>
          <p className="lede">
            Liphr encrypts each entry on your device using a master password only you know.
            What we store is scrambled text we can't read.
          </p>
          {user ? (
            <Link to="/vault" className="btn">Open my vault</Link>
          ) : (
            <button className="btn" onClick={() => onOpenAuth('signup')}>Create a free account</button>
          )}
        </div>

        <div className="demo" aria-label="Example of how an entry is stored">
          <div className="demo-side">
            <h2>What you see</h2>
            <dl>
              <dt>Website</dt><dd>netflix.com</dd>
              <dt>Username</dt><dd>sam@example.com</dd>
              <dt>Password</dt><dd>correct-horse-42</dd>
            </dl>
          </div>
          <div className="demo-side stored">
            <h2>What we store</h2>
            <dl>
              <dt>Website</dt><dd>q3VnT0b1mZk8…xA==</dd>
              <dt>Username</dt><dd>Hs2eW9PdL4c7…Rg==</dd>
              <dt>Password</dt><dd>7yFcN1uQe0aB…Vw==</dd>
            </dl>
          </div>
        </div>
      </section>

      <section className="facts">
        <div>
          <h3>Encrypted on your device</h3>
          <p>Your master password turns into an encryption key in your browser. It is never sent anywhere.</p>
        </div>
        <div>
          <h3>Room for 100 passwords</h3>
          <p>Each account can hold up to 100 entries, with a notes field for anything else you need to remember.</p>
        </div>
        <div>
          <h3>Only you hold the key</h3>
          <p>That also means we can't reset your master password. If you lose it, your saved entries can't be recovered.</p>
        </div>
      </section>
    </main>
  )
}
