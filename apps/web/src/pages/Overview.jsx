import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import StatCard from '../components/StatCard.jsx'

const BASE = 'http://localhost:8000'

function fmt(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleTimeString()
}

export default function Overview() {
  const [metrics, setMetrics] = useState(null)
  const [audit, setAudit] = useState(null)
  const nav = useNavigate()

  const load = () => {
    fetch(`${BASE}/metrics`).then(r => r.json()).then(setMetrics).catch(() => {})
    fetch(`${BASE}/audit?limit=5`).then(r => r.json()).then(setAudit).catch(() => {})
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  const m = metrics || {}
  const events = audit?.events || []

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Overview</div>
          <div className="section-sub">Live metrics — auto-refresh every 30s</div>
        </div>
      </div>

      <div className="stat-grid">
        <StatCard title="Total Actions" value={m.total_verifications} color="var(--blue)" subtitle="all verify calls" />
        <StatCard title="Allowed" value={m.allowed_count} color="var(--green)" subtitle="passed all 12 checks" />
        <StatCard title="Blocked" value={m.blocked_count} color="var(--red)" subtitle="stopped by gateway" />
        <StatCard title="Injections Blocked" value={m.injection_blocks} color="var(--orange)" subtitle="LLM01 — prompt injection" />
        <StatCard title="Schema Violations" value={m.schema_blocks} color="var(--purple)" subtitle="LLM05 — improper output" />
        <StatCard title="Rate Limited" value={m.rate_limit_blocks} color="#eab308" subtitle="LLM10 — unbounded use" />
      </div>

      <div className="card mb-16" style={{ marginBottom: 16 }}>
        <div className="section-header">
          <span className="section-title">Current Audit Chain State</span>
        </div>
        <div className="two-col">
          <div>
            <div className="text-muted text-sm" style={{ marginBottom: 6 }}>MMR Root Hash</div>
            <div className="hash-display">{m.mmr_root || '—'}</div>
          </div>
          <div>
            <div className="text-muted text-sm" style={{ marginBottom: 6 }}>Total Leaf Count</div>
            <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--blue)', padding: '14px 0' }}>
              {m.mmr_leaf_count ?? '—'}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="section-header">
          <span className="section-title">Recent Audit Events</span>
          <span className="section-sub">Last 5</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Agent</th>
                <th>Action</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr><td colSpan={4} style={{ color: 'var(--muted)', textAlign: 'center' }}>No events yet</td></tr>
              )}
              {events.map(e => (
                <tr key={e.record_id} onClick={() => e.evidence_id && nav(`/evidence/${e.evidence_id}`)}>
                  <td className="mono">{fmt(e.verified_at)}</td>
                  <td className="mono">{(e.agent_id || '').slice(0, 16)}</td>
                  <td>{e.action_submitted}</td>
                  <td>
                    <span className={`badge ${e.allowed ? 'badge-green' : 'badge-red'}`}>
                      {e.allowed ? 'ALLOWED' : 'BLOCKED'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
