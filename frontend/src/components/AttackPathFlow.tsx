import type { AttackPath } from '@/types'
import { NODE_W, NODE_H, GAP, ROW_H, scoreColor, buildNodes } from './attackPathFlow.utils'

/** Renders one attack path as a horizontal kill-chain diagram: entry node,
 * through each hop (colored by that hop's own risk score), to the target
 * node, with the relation type labeled on each connecting edge. Always
 * rendered — replaces the previous pattern of a one-line text summary
 * that only revealed the actual chain after an expand click. */
export function AttackPathFlow({ path }: { path: AttackPath }) {
  const nodes = buildNodes(path)
  const width = nodes.length * NODE_W + (nodes.length - 1) * GAP + 16
  const height = ROW_H

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ maxWidth: width }} className="overflow-visible">
      {nodes.map((node, i) => {
        const x = 8 + i * (NODE_W + GAP)
        const y = (height - NODE_H) / 2
        const color = node.kind === 'hop' ? scoreColor(node.score) : node.kind === 'entry' ? '#22D3EE' : '#A78BFA'
        const cx = x + NODE_W / 2

        return (
          <g key={i}>
            {i > 0 && (
              <g>
                <line
                  x1={x - GAP} y1={height / 2} x2={x - 4} y2={height / 2}
                  stroke="#DDE1E8" strokeWidth={1.5} markerEnd="url(#apArrow)"
                />
                {node.relationFromPrev && (
                  <text x={x - GAP / 2} y={height / 2 - 8} textAnchor="middle" fontSize="9"
                    fill="#636873" fontFamily="monospace">
                    {node.relationFromPrev.replace(/_/g, ' ')}
                  </text>
                )}
              </g>
            )}
            <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={7}
              fill={node.kind === 'hop' ? `${color}1A` : 'transparent'}
              stroke={color} strokeWidth={1.5} />
            <text x={cx} y={y + 18} textAnchor="middle" fontSize="9" fill={color}
              fontWeight={600} letterSpacing="0.04em" fontFamily="monospace">
              {node.type.toUpperCase()}
            </text>
            <text x={cx} y={y + 34} textAnchor="middle" fontSize="11" fill="#12151C" fontWeight={500}>
              {node.label.length > 18 ? node.label.slice(0, 17) + '…' : node.label}
            </text>
            {node.score != null && (
              <text x={cx} y={y + 47} textAnchor="middle" fontSize="9" fill={color} fontFamily="monospace">
                risk {node.score.toFixed(0)}
              </text>
            )}
          </g>
        )
      })}
      <defs>
        <marker id="apArrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0 0L8 4L0 8Z" fill="#DDE1E8" />
        </marker>
      </defs>
    </svg>
  )
}
