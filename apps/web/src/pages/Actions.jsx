import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import OWASPBadge from '../components/OWASPBadge.jsx'

const BASE = 'http://localhost:8000'

function fmt(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleTimeString()
}

function owaspFromReason(reason, allowed) {
  if (!reason) return allowed ? null : 'LLM06'
  if (reason.includes('INJECTION')) return 'LLM01'
  if (reason.includes('SCHEMA')) return 'LLM05'
  if (reason.includes('RATE_LIMIT')) return 'LLM10'
  if (!allowed) return 'LLM06'
  return null
}

function trunc(s, n) {
  if (!s) return '—'
  return s.length > n ? s.slice(0, n) + '…' : s
}

export default function Actions() {
  const [data, setData] = useState(null)
  const nav = useNavigate()

  const load = () => {
    fetch(`${BASE}/audit?limit=50`)
      .then(r => r.json())
      .then(setData)
      .catch(() => {})
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [])

  const events = data?.events || []
  if (events.length > 0) console.log('First audit event:', events[0])

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Actions</div>
          <div className="section-sub">Last 50 verification events — auto-refresh every 15s</div>
        </div>
        <span className="section-sub">{events.length} records</span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent ID</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Decision</th>
              <th>OWASP</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr><td colSpan={7} style={{ color: 'var(--muted)', textAlign: 'center' }}>No events yet</td></tr>
            )}
            {events.map(e => {
              const owasp = owaspFromReason(e.reason, e.allowed)
              return (
                <tr key={e.record_id} onClick={() => e.evidence_id && nav(`/evidence/${e.evidence_id}`)}>
                  <td className="mono">{fmt(e.verified_at)}</td>
                  <td className="mono">{(e.agent_id || '').slice(0, 8)}</td>
                  <td>{e.action_submitted}</td>
                  <td>{trunc(e.resource_submitted, 30)}</td>
                  <td>
                    <span className={`badge ${e.allowed ? 'badge-green' : 'badge-red'}`}>
                      {e.allowed ? 'ALLOWED' : 'BLOCKED'}
                    </span>
                  </td>
                  <td><OWASPBadge label={owasp} /></td>
                  <td>
                    {e.evidence_id
                      ? <span style={{ color: 'var(--blue)', fontSize: 11 }} className="mono">{e.evidence_id.slice(0, 8)}…</span>
                      : '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
