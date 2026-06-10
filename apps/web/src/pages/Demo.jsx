import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import OWASPBadge from '../components/OWASPBadge.jsx'

const BASE = 'http://localhost:8000'

const ATTACKS = [
  {
    id: 'authorized',
    name: 'Authorized Action',
    owasp: 'LLM06',
    desc: 'Full happy-path flow. All 12 checks pass.',
    endpoint: '/demo/authorized',
    expectBlocked: false,
  },
  {
    id: 'tamper',
    name: 'Tampered Payload',
    owasp: 'LLM06',
    desc: 'Payload modified after ticket issuance. Stopped at Check 8.',
    endpoint: '/demo/tamper',
    expectBlocked: true,
  },
  {
    id: 'replay',
    name: 'Replay Attack',
    owasp: 'LLM06',
    desc: 'Same ticket submitted twice. Stopped at Check 5 — JTI replay.',
    endpoint: '/demo/replay',
    expectBlocked: true,
  },
  {
    id: 'overscope',
    name: 'Over-Scoped Action',
    owasp: 'LLM06',
    desc: 'Agent attempts an action beyond its approved scope. Check 6.',
    endpoint: '/demo/overscope',
    expectBlocked: true,
  },
  {
    id: 'expired',
    name: 'Expired Ticket',
    owasp: 'LLM06',
    desc: 'Ticket with past expiry submitted. Stopped at Check 4.',
    endpoint: '/demo/expired',
    expectBlocked: true,
  },
  {
    id: 'fake',
    name: 'Fake Agent',
    owasp: 'LLM06',
    desc: 'Unregistered agent submits a forged ticket. Check 1.',
    endpoint: '/demo/fake',
    expectBlocked: true,
  },
  {
    id: 'injection',
    name: 'Prompt Injection',
    owasp: 'LLM01',
    desc: 'Injection pattern in intent purpose. Blocked before policy.',
    endpoint: '/demo/injection',
    expectBlocked: true,
  },
  {
    id: 'schema',
    name: 'Schema Violation',
    owasp: 'LLM05',
    desc: 'Extra field (bcc) not in declared schema. Stopped at Check 9.',
    endpoint: '/demo/schema',
    expectBlocked: true,
  },
  {
    id: 'ratelimit',
    name: 'Rate Limit',
    owasp: 'LLM10',
    desc: '6 requests with limit=5. 6th blocked at policy evaluation.',
    endpoint: '/demo/ratelimit',
    expectBlocked: true,
  },
  {
    id: 'mmr-tamper',
    name: 'MMR Audit Tamper',
    owasp: 'LLM06',
    desc: 'Directly corrupt an MMR leaf. Integrity violation detected.',
    endpoint: '/demo/mmr-tamper',
    expectBlocked: true,
  },
]

function AttackCard({ attack, nav }) {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    setLoading(true)
    setResult(null)
    try {
      const r = await fetch(`${BASE}${attack.endpoint}`, { method: 'POST' })
      setResult(await r.json())
    } catch (e) {
      setResult({ result: 'ERROR', reason: e.message })
    } finally {
      setLoading(false)
    }
  }

  const isBlocked = result?.result === 'BLOCKED'
  const isAllowed = result?.result === 'ALLOWED'

  return (
    <div className="demo-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <span className="demo-card-title">{attack.name}</span>
        <OWASPBadge label={attack.owasp} />
      </div>
      <div className="demo-card-desc">{attack.desc}</div>
      <button className="btn btn-primary" onClick={run} disabled={loading} style={{ fontSize: 12, padding: '6px 12px' }}>
        {loading ? <><span className="spinner" style={{ width: 12, height: 12 }} /> Running…</> : 'Run Attack'}
      </button>
      {result && (
        <div className={`demo-result ${isAllowed ? 'allowed' : isBlocked ? 'blocked' : ''}`}>
          {isAllowed && '✓ ALLOWED'}
          {isBlocked && '✗ BLOCKED'}
          {result.result === 'ERROR' && '⚠ ERROR'}
          {result.reason && <pre>{result.reason}</pre>}
          {result.diff && Object.keys(result.diff).length > 0 && (
            <pre>{JSON.stringify(result.diff, null, 2)}</pre>
          )}
          {result.evidence_id && (
            <div style={{ marginTop: 6 }}>
              <a
                href={`/evidence/${result.evidence_id}`}
                style={{ color: 'var(--blue)', fontSize: 11, textDecoration: 'underline' }}
              >
                View Evidence →
              </a>
            </div>
          )}
          {result.mmr_leaf_index != null && (
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
              MMR leaf: {result.mmr_leaf_index} · {result.duration_ms}ms
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Demo() {
  const nav = useNavigate()
  const [fullResult, setFullResult] = useState(null)
  const [fullLoading, setFullLoading] = useState(false)
  const [fullProgress, setFullProgress] = useState([])

  const runFull = async () => {
    setFullLoading(true)
    setFullResult(null)
    setFullProgress([])
    try {
      for (const attack of ATTACKS) {
        setFullProgress(p => [...p, { name: attack.name, status: 'running' }])
        const r = await fetch(`${BASE}${attack.endpoint}`, { method: 'POST' })
        const d = await r.json()
        setFullProgress(p => p.map(x => x.name === attack.name ? { ...x, status: d.result, data: d } : x))
      }
      setFullLoading(false)
    } catch (e) {
      setFullLoading(false)
    }
  }

  const allowed = fullProgress.filter(x => x.status === 'ALLOWED').length
  const blocked = fullProgress.filter(x => x.status === 'BLOCKED').length

  return (
    <div>
      <div className="section-header" style={{ marginBottom: 20 }}>
        <div>
          <div className="section-title">Demo Control Panel</div>
          <div className="section-sub">Run attacks directly from the browser</div>
        </div>
        <button className="btn btn-primary" onClick={runFull} disabled={fullLoading}>
          {fullLoading ? <><span className="spinner" /> Running all…</> : '▶ Run Full Demo'}
        </button>
      </div>

      {fullProgress.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>
            Full Demo Progress
            {!fullLoading && (
              <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--muted)', marginLeft: 12 }}>
                {blocked} blocked · {allowed} allowed
              </span>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {fullProgress.map((p, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background:
                  p.status === 'running' ? 'var(--orange)' :
                  p.status === 'BLOCKED' ? 'var(--green)' :
                  p.status === 'ALLOWED' ? 'var(--blue)' : 'var(--muted)' }} />
                <span style={{ minWidth: 180 }}>{p.name}</span>
                <span style={{ fontSize: 11, color:
                  p.status === 'running' ? 'var(--orange)' :
                  p.status === 'BLOCKED' ? 'var(--green)' :
                  p.status === 'ALLOWED' ? 'var(--blue)' : 'var(--muted)' }}>
                  {p.status === 'running' ? '⏳ running…' :
                   p.status === 'BLOCKED' ? '✗ BLOCKED' :
                   p.status === 'ALLOWED' ? '✓ ALLOWED' : p.status}
                </span>
                {p.data?.reason && <span style={{ fontSize: 11, color: 'var(--muted)' }}>{p.data.reason}</span>}
                {p.data?.duration_ms != null && <span style={{ fontSize: 11, color: 'var(--border)', marginLeft: 'auto' }}>{p.data.duration_ms}ms</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="demo-grid">
        {ATTACKS.map(a => <AttackCard key={a.id} attack={a} nav={nav} />)}
      </div>
    </div>
  )
}
