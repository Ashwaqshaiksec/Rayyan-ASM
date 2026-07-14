import { Search } from 'lucide-react'

interface GlobalSearchProps {
  onOpen: () => void
}

// The header's "hero" search entry point. Deliberately not an input of its
// own — commercial ASM search bars (Censys, Shodan) make search the single
// focal entry point rather than splitting attention between a small inline
// box and a separate power-user shortcut, so this renders as a large,
// button-styled bar that opens the same CommandPalette that Ctrl+K opens.
// One search experience, reachable two ways, instead of two competing ones.
export default function GlobalSearch({ onOpen }: GlobalSearchProps) {
  return (
    <button
      onClick={onOpen}
      className="w-full flex items-center gap-2.5 bg-surface-2 border border-border rounded-lg pl-3.5 pr-3 py-2 text-left text-sm text-text-muted hover:border-accent-cyan/40 hover:text-text-secondary transition-colors"
    >
      <Search className="w-4 h-4 flex-shrink-0" />
      <span className="flex-1 truncate">Search domains, IPs, CVEs, ASNs…</span>
      <kbd className="hidden sm:inline-flex items-center gap-0.5 flex-shrink-0 px-1.5 py-0.5 rounded-md border border-border bg-surface-1 text-[10px] font-mono text-text-muted">
        ⌘K
      </kbd>
    </button>
  )
}
