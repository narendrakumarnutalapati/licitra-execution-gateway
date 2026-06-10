export default function StatCard({ title, value, color, subtitle }) {
  return (
    <div className="stat-card" style={{ borderLeftColor: color }}>
      <div className="stat-title">{title}</div>
      <div className="stat-value" style={{ color }}>{value ?? '—'}</div>
      {subtitle && <div className="stat-subtitle">{subtitle}</div>}
    </div>
  )
}
