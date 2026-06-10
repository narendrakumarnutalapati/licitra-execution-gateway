export default function OWASPBadge({ label }) {
  if (!label) return null
  return <span className={`owasp-badge owasp-${label}`}>{label}</span>
}
