import { useState } from 'react'

const BASE = 'http://localhost:8000'

const STEPS = [
  { n: 1, text: 'Run any attack on the Demo page' },
  { n: 2, text: 'Click "View Evidence" on the result card' },
  { n: 3, text: 'On the Evidence page, click "Copy Proof JSON"' },
  { n: 4, text: 'Come back here and paste it into the form below' },
]

export default function Verify() {
  const [leafHash, setLeafHash] = useState('')
  const [proofJson, setProofJson] = useState('')
  const [rootHash, setRootHash] = useState('')
  const [leafIndex, setLeafIndex] = useState('')
  const [result, setResult] = useState(null)
  const [err, setErr] = useState(null)
  const [loading, setLoading] = useState(false)
  const [autoFilling, setAutoFilling] = useState(false)
  const [autoFillMsg, setAutoFillMsg] = useState(null)

  const handleSubmit = async e => {
    e.preventDefault()
    setErr(null)
    setResult(null)
    let proof
    try {
      proof = JSON.parse(proofJson)
    } catch {
      setErr('Proof JSON is not valid JSON')
      return
    }
    setLoading(true)
    try {
      const r = await fetch(`${BASE}/audit/verify-proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          leaf_hash: leafHash,
          proof,
          root: rootHash,
          leaf_index: parseInt(leafIndex, 10),
        }),
      })
      const d = await r.json()
      setResult(d)
    } catch (e) {
      setErr(e.message)
    } finally {
      setLoading(false)
    }
  }

  const handleClear = () => {
    setLeafHash('')
    setProofJson('')
    setRootHash('')
    setLeafIndex('')
    setResult(null)
    setErr(null)
    setAutoFillMsg(null)
  }

  const handleAutoFill = async () => {
    setAutoFilling(true)
    setAutoFillMsg(null)
    setErr(null)
    try {
      const auditRes = await fetch(`${BASE}/audit?limit=1`)
      const auditData = await auditRes.json()
      const events = auditData.events || []
      if (!events.length) { setErr('No audit events found. Run a demo first.'); setAutoFilling(false); return }
      const eid = events[0].evidence_id
      if (!eid) { setErr('Latest event has no evidence record yet.'); setAutoFilling(false); return }
      const evRes = await fetch(`${BASE}/evidence/${eid}`)
      const ev = await evRes.json()
      setLeafHash(ev.mmr_leaf_hash || '')
      setProofJson(JSON.stringify(ev.mmr_proof || {}, null, 2))
      setRootHash(ev.mmr_root || '')
      setLeafIndex(ev.mmr_leaf_index != null ? String(ev.mmr_leaf_index) : '')
      setAutoFillMsg(`Auto-filled from evidence ${eid}`)
      setResult(null)
    } catch (e) {
      setErr('Auto-fill failed: ' + e.message)
    } finally {
      setAutoFilling(false)
    }
  }

  return (
    <div style={{ maxWidth: 680 }}>
      <div className="section-header" style={{ marginBottom: 20 }}>
        <div>
          <div className="section-title">MMR Proof Verifier</div>
          <div className="section-sub">Manually verify a Merkle Mountain Range inclusion proof</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16, borderColor: 'rgba(59,130,246,0.25)' }}>
        <div className="section-title" style={{ marginBottom: 12, fontSize: 13 }}>How to get a proof to verify</div>
        <ol style={{ margin: 0, padding: '0 0 0 18px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {STEPS.map(s => (
            <li key={s.n} style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>
              <span style={{ color: 'var(--text)' }}>{s.text}</span>
            </li>
          ))}
        </ol>
        <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <button className="btn btn-ghost" type="button" onClick={handleAutoFill} disabled={autoFilling}>
            {autoFilling ? <><span className="spinner" /> Fetching…</> : '⚡ Auto-fill from latest event'}
          </button>
          {autoFillMsg && (
            <span style={{ fontSize: 12, color: 'var(--green)' }}>{autoFillMsg}</span>
          )}
        </div>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Leaf Hash</label>
            <input
              type="text"
              placeholder="64-char hex hash"
              value={leafHash}
              onChange={e => setLeafHash(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>Proof JSON</label>
            <textarea
              placeholder={'{\n  "siblings": [...],\n  "peaks": [...],\n  "peak_index": 0\n}'}
              value={proofJson}
              onChange={e => setProofJson(e.target.value)}
              style={{ minHeight: 140 }}
              required
            />
          </div>
          <div className="form-group">
            <label>Root Hash</label>
            <input
              type="text"
              placeholder="64-char hex root"
              value={rootHash}
              onChange={e => setRootHash(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>Leaf Index</label>
            <input
              type="number"
              min="0"
              placeholder="0"
              value={leafIndex}
              onChange={e => setLeafIndex(e.target.value)}
              required
            />
          </div>
          {err && <div style={{ color: 'var(--red)', fontSize: 13, marginBottom: 12 }}>{err}</div>}
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-primary" type="submit" disabled={loading}>
              {loading ? <><span className="spinner" /> Verifying…</> : 'Verify Proof'}
            </button>
            <button className="btn btn-ghost" type="button" onClick={handleClear}>Clear</button>
          </div>
        </form>
      </div>

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          {result.valid ? (
            <div>
              <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--green)', marginBottom: 12 }}>VALID ✓</div>
              <div className="detail-list">
                <div className="detail-item">
                  <span className="detail-key">leaf_index</span>
                  <span className="detail-val mono">{result.leaf_index}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">proof_size</span>
                  <span className="detail-val mono">{result.proof_size}</span>
                </div>
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--red)', marginBottom: 12 }}>INVALID ✗</div>
              <div style={{ color: 'var(--muted)', fontSize: 13 }}>{result.message || 'Proof verification failed'}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
