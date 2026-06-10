import { useEffect, useState } from 'react'
import OWASPBadge from '../components/OWASPBadge.jsx'

const BASE = 'http://localhost:8000'

const OUT_OF_SCOPE = [
  'LLM02', 'LLM03', 'LLM04', 'LLM07', 'LLM08', 'LLM09',
]

const CARDS = [
  {
    label: 'LLM01',
    title: 'Prompt Injection',
    color: 'var(--red)',
    metric: 'injection_blocks',
    description: 'Injection scan runs on every intent at creation time and re-scans every payload at verify check 10. HIGH severity patterns block immediately.',
  },
  {
    label: 'LLM05',
    title: 'Improper Output Handling',
    color: 'var(--orange)',
    metric: 'schema_blocks',
    description: 'Output schema declared at agent registration. Every payload validated against declared schema at verify check 9. Additional properties blocked.',
  },
  {
    label: 'LLM06',
    title: 'Excessive Agency',
    color: 'var(--blue)',
    metric: 'blocked_count',
    description: '12-check cryptographic verification. Payload hash binding, action binding, resource binding, JTI replay prevention, signature verification.',
  },
  {
    label: 'LLM10',
    title: 'Unbounded Consumption',
    color: 'var(--purple)',
    metric: 'rate_limit_blocks',
    description: 'Per-agent hourly action limits, daily action limits, and daily budget caps enforced at policy evaluation before ticket issuance.',
  },
]

export default function OWASP() {
  const [metrics, setMetrics] = useState(null)

  useEffect(() => {
    fetch(`${BASE}/metrics`).then(r => r.json()).then(setMetrics).catch(() => {})
  }, [])

  const m = metrics || {}

  return (
    <div>
      <div className="section-header" style={{ marginBottom: 20 }}>
        <div>
          <div className="section-title">OWASP Coverage</div>
          <div className="section-sub">LLM Top 10 risks addressed by LICITRA</div>
        </div>
      </div>

      <div className="owasp-grid">
        {CARDS.map(c => (
          <div key={c.label} className="owasp-card" style={{ borderColor: c.color + '40' }}>
            <div className="owasp-card-header">
              <OWASPBadge label={c.label} />
              <span style={{ fontSize: 14, fontWeight: 600 }}>{c.title}</span>
            </div>
            <div className="owasp-count" style={{ color: c.color }}>
              {m[c.metric] ?? '—'}
            </div>
            <p>{c.description}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="section-title" style={{ marginBottom: 14 }}>Out of Scope</div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {OUT_OF_SCOPE.map(r => (
                <tr key={r}>
                  <td><OWASPBadge label={r} /></td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>
                    Out of scope — see docs/OWASP_COVERAGE.md
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
