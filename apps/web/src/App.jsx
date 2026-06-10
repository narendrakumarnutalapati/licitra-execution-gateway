import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import NavBar from './components/NavBar.jsx'
import Overview from './pages/Overview.jsx'
import Actions from './pages/Actions.jsx'
import Evidence from './pages/Evidence.jsx'
import Verify from './pages/Verify.jsx'
import MMR from './pages/MMR.jsx'
import OWASP from './pages/OWASP.jsx'
import Demo from './pages/Demo.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <NavBar />
        <main className="page-content">
          <Routes>
            <Route path="/" element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<Overview />} />
            <Route path="/actions" element={<Actions />} />
            <Route path="/evidence/:id" element={<Evidence />} />
            <Route path="/verify" element={<Verify />} />
            <Route path="/mmr" element={<MMR />} />
            <Route path="/owasp" element={<OWASP />} />
            <Route path="/demo" element={<Demo />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
