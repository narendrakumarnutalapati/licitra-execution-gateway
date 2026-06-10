import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'

const BASE = 'http://localhost:8000'

function Row({ k, v }) {
  return (
    <div className="detail-item">
      <span className="detail-key">{k}</span>
      <span className="detail-val mono">{v ?? '—'}</span>
    </div>
  )
}

export default function Evidence() {
  const { id } = useParams()
  const nav = useNavigate()
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!id || id === '—') { setErr('No evidence ID provided. Navigate from the Actions page.'); return }
    fetch(`${BASE}/evidence/${id}`)
      .then(r => { if (!r.ok) throw new Error('Not found'); return r.json() })
      .then(setData)
      .catch(e => setErr(e.message))
  }, [id])

  if (err) return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 16 }} onClick={() => nav(-1)}>← Back</button>
      <div className="card" style={{ color: 'var(--red)' }}>{err}</div>
    </div>
  )
  if (!data) return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 16 }} onClick={() => nav(-1)}>← Back</button>
      <div className="card"><span className="spinner" /> Loading…</div>
    </div>
  )

  const allowed = data.decision === 'ALLOWED'
  const proof = data.mmr_proof || {}
  const siblings = proof.siblings || []

  const handleCopyProof = () => {
    const obj = { leaf_hash: data.mmr_leaf_hash, proof: data.mmr_proof, root: data.mmr_root, leaf_index: data.mmr_leaf_index }
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 16 }} onClick={() => nav(-1)}>← Back</button>

      <div className={`decision-banner ${allowed ? 'allowed' : 'blocked'}`}>
        {allowed ? '✓ ALLOWED' : '✗ BLOCKED'}
        {!allowed && data.reason && <div style={{ fontSize: 14, marginTop: 8, fontWeight: 400 }}>{data.reason}</div>}
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="section-title" style={{ marginBottom: 14 }}>Identifiers</div>
          <div className="detail-list">
            <Row k="evidence_id" v={data.evidence_id} />
            <Row k="intent_id" v={data.intent_id} />
            <Row k="decision_id" v={data.decision_id} />
            <Row k="ticket_id" v={data.ticket_id} />
            <Row k="agent_id" v={data.agent_id} />
          </div>
        </div>
        <div className="card">
          <div className="section-title" style={{ marginBottom: 14 }}>Action Details</div>
          <div className="detail-list">
            <Row k="action" v={data.action} />
            <Row k="resource" v={data.resource} />
            <Row k="reason" v={data.reason} />
            <Row k="created_at" v={data.created_at} />
          </div>
        </div>
      </div>

      {data.diff && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Diff</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '6px 10px', fontSize: 11, color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>Field</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', fontSize: 11, color: 'var(--green)', borderBottom: '1px solid var(--border)' }}>Expected</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', fontSize: 11, color: 'var(--red)', borderBottom: '1px solid var(--border)' }}>Actual</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(data.diff).map(([k, v]) => (
                  <tr key={k} style={{ background: 'rgba(239,68,68,0.06)' }}>
                    <td className="mono" style={{ padding: '6px 10px', color: 'var(--muted)', fontSize: 12 }}>{k}</td>
                    <td className="mono" style={{ padding: '6px 10px', color: 'var(--green)', fontSize: 12, wordBreak: 'break-all' }}>
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </td>
                    <td className="mono" style={{ padding: '6px 10px', color: 'var(--muted)', fontSize: 12 }}>—</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data.schema_violations && data.schema_violations.length > 0 && (
        <div className="card" style={{ marginBottom: 16, borderColor: 'rgba(245,158,11,0.4)' }}>
          <div className="section-title" style={{ marginBottom: 10, color: 'var(--orange)' }}>Schema Violations</div>
          {data.schema_violations.map((v, i) => (
            <div key={i} className="mono text-sm" style={{ padding: '4px 0', color: 'var(--orange)' }}>• {v}</div>
          ))}
        </div>
      )}

      {data.injection_findings && data.injection_findings.length > 0 && (
        <div className="card" style={{ marginBottom: 16, borderColor: 'rgba(239,68,68,0.4)' }}>
          <div className="section-title" style={{ marginBottom: 10, color: 'var(--red)' }}>Injection Findings</div>
          {data.injection_findings.map((f, i) => (
            <div key={i} className="mono text-sm" style={{ padding: '4px 0', color: 'var(--red)' }}>
              • {typeof f === 'object' ? JSON.stringify(f) : f}
            </div>
          ))}
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 14 }}>MMR Inclusion Proof</div>
        <div className="detail-list" style={{ marginBottom: 14 }}>
          <div className="detail-item">
            <span className="detail-key">leaf_index</span>
            <span className="detail-val mono">{data.mmr_leaf_index ?? '—'}</span>
          </div>
          <div className="detail-item">
            <span className="detail-key">leaf_hash</span>
            <span className="detail-val mono" style={{ color: 'var(--blue)' }}>
              {data.mmr_leaf_hash ? data.mmr_leaf_hash.slice(0, 20) + '…' : '—'}
            </span>
          </div>
          <div className="detail-item">
            <span className="detail-key">mmr_root</span>
            <span className="detail-val mono" style={{ color: 'var(--blue)' }}>
              {data.mmr_root ? data.mmr_root.slice(0, 20) + '…' : '—'}
            </span>
          </div>
          <div className="detail-item">
            <span className="detail-key">proof_size</span>
            <span className="detail-val mono">{data.mmr_proof_size ?? siblings.length}</span>
          </div>
        </div>
        {siblings.length > 0 && (
          <div>
            <div className="text-muted text-sm" style={{ marginBottom: 6 }}>Siblings</div>
            {siblings.map((s, i) => (
              <div key={i} className="mono text-sm" style={{ padding: '3px 0', color: 'var(--muted)' }}>
                [{i}] {s}
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 10 }}>
        <a
          className="btn btn-primary"
          href={`${BASE}/evidence/${data.evidence_id}/pdf`}
          target="_blank"
          rel="noreferrer"
        >
          Download PDF
        </a>
        <button className="btn btn-ghost" onClick={handleCopyProof}>
          {copied ? 'Copied ✓' : 'Copy Proof JSON'}
        </button>
      </div>
    </div>
  )
}
