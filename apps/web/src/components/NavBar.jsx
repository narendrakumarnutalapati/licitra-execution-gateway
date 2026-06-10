import { NavLink } from 'react-router-dom'

const LINKS = [
  { to: '/overview', label: 'Overview' },
  { to: '/actions', label: 'Actions' },
  { to: '/mmr', label: 'MMR' },
  { to: '/owasp', label: 'OWASP' },
  { to: '/verify', label: 'Verify' },
  { to: '/demo', label: 'Demo' },
]

export default function NavBar() {
  return (
    <nav className="navbar">
      <div className="navbar-brand">LICITRA <span>Gateway</span></div>
      <div className="navbar-links">
        {LINKS.map(l => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) => isActive ? 'active' : ''}
            end={l.to === '/overview'}
          >
            {l.label}
          </NavLink>
        ))}
      </div>
    </nav>
  )
}
