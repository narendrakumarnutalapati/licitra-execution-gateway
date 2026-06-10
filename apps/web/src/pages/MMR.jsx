import { useEffect, useState } from 'react'

const BASE = 'http://localhost:8000'

export default function MMR() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  const load = () => {
    setLoading(true)
    fetch(`${BASE}/audit/root`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const intact = data?.integrity === 'INTACT'

  return (
    <div style={{ maxWidth: 700 }}>
      <div className="section-header" style={{ marginBottom: 20 }}>
        <div>
          <div className="section-title">MMR Audit Chain</div>
          <div className="section-sub">Merkle Mountain Range integrity status</div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? <span className="spinner" /> : '↻'} Refresh
        </button>
      </div>

      {data && (
        <>
          <div className="card" style={{ marginBottom: 16, textAlign: 'center' }}>
            <div className={`mmr-status ${intact ? 'intact' : 'tampered'}`}>
              {intact ? '✓ INTACT' : '✗ TAMPERED'}
            </div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>
              {intact
                ? 'All audit records are cryptographically consistent.'
                : 'One or more audit records have been modified after the fact.'}
            </div>
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <div className="text-muted text-sm" style={{ marginBottom: 6 }}>MMR Root Hash</div>
            <div className="hash-display">{data.mmr_root}</div>
          </div>

          <div className="two-col" style={{ marginBottom: 16 }}>
            <div className="card">
              <div className="text-muted text-sm" style={{ marginBottom: 6 }}>Total Leaf Count</div>
              <div style={{ fontSize: 36, fontWeight: 800, color: 'var(--blue)' }}>{data.leaf_count}</div>
            </div>
            <div className="card">
              <div className="text-muted text-sm" style={{ marginBottom: 6 }}>Last Integrity Check</div>
              <div className="mono" style={{ fontSize: 13, color: 'var(--text)', marginTop: 8 }}>
                {data.last_check ? new Date(data.last_check).toLocaleString() : '—'}
              </div>
            </div>
          </div>

          <div className="card" style={{ background: 'rgba(59,130,246,0.05)', borderColor: 'rgba(59,130,246,0.2)' }}>
            <div className="section-title" style={{ marginBottom: 8 }}>About This Hash</div>
            <p style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1.7 }}>
              This hash represents the cryptographic state of all <strong style={{ color: 'var(--text)' }}>{data.leaf_count}</strong> audit
              events. Any modification to any historical event would change this hash. The MMR structure
              allows efficient inclusion proofs — any single event can be verified against this root
              without replaying the entire chain.
            </p>
          </div>
        </>
      )}

      {!data && !loading && (
        <div className="card" style={{ color: 'var(--muted)' }}>Could not connect to API.</div>
      )}
    </div>
  )
}
