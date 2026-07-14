import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useEffect, useRef, useState } from 'react'
import { LayoutDashboard, Bell, Settings, LogOut, ChevronDown, Radar, Search as SearchIcon, HelpCircle } from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/utils/api'
import { navGroups, allNavItems } from '@/utils/navigation'
import clsx from 'clsx'
import GlobalSearch from './GlobalSearch'
import CommandPalette from './CommandPalette'
import OnboardingTutorial from './OnboardingTutorial'
import HelpPanel from './HelpPanel'

type NavItem = { label: string; path: string; icon: typeof LayoutDashboard; role?: string }

const allItems: NavItem[] = allNavItems

export default function Layout() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const location = useLocation()
  const menuRef = useRef<HTMLDivElement>(null)

  const activeItem = allItems.find((item) => location.pathname.startsWith(item.path))

  // Close the menu on route change and on outside click.
  useEffect(() => { setMenuOpen(false) }, [location.pathname])
  useEffect(() => { setPaletteOpen(false) }, [location.pathname])
  useEffect(() => { setHelpOpen(false) }, [location.pathname])

  // Global shortcut: Ctrl/Cmd + K opens the command palette from anywhere
  // in the app, not just when the header search bar happens to be focused.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => {
          const next = !v
          if (next) { setHelpOpen(false); setMenuOpen(false) }
          return next
        })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // The header nav menu, command palette, and help panel are all top-layer
  // overlays sharing the same z-index — only one should be open at a time.
  const openPalette = () => { setHelpOpen(false); setMenuOpen(false); setPaletteOpen(true) }
  const openHelp = () => { setPaletteOpen(false); setMenuOpen(false); setHelpOpen(true) }

  useEffect(() => {
    if (!menuOpen) return
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [menuOpen])

  const handleLogout = async () => {
    try {
      await authApi.logout()
    } catch (err) {
      console.error('Logout request failed:', err)
    }
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-surface-0">
      <header className="relative z-30 flex-shrink-0 h-14 border-b border-border bg-surface-1 shadow-sm px-4 flex items-center justify-between">
        <NavLink to="/dashboard" className="flex items-center gap-3 flex-shrink-0 group">
          <div className="reticle flex-shrink-0 w-8 h-8 m-1 bg-surface-2 border border-border flex items-center justify-center group-hover:border-accent-cyan/40 transition-colors">
            <Radar className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="hidden sm:block">
            <div className="text-sm font-semibold text-text-primary leading-tight tracking-tight font-mono">RAYYAN<span className="text-accent-cyan">_</span>ASM</div>
            <div className="text-[10px] text-text-muted leading-tight font-mono uppercase tracking-wider">Attack Surface Mgmt</div>
          </div>
        </NavLink>

        <div ref={menuRef} className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
          <button
            onClick={() => { setPaletteOpen(false); setHelpOpen(false); setMenuOpen((v) => !v) }}
            className={clsx(
              'flex items-center gap-2 px-4 py-1.5 rounded border text-xs font-mono uppercase tracking-wider transition-colors duration-150',
              menuOpen || activeItem
                ? 'border-accent-cyan/40 bg-accent-cyan/10 text-accent-cyan'
                : 'border-border bg-surface-2 text-text-secondary hover:text-text-primary hover:bg-surface-3'
            )}
          >
            {activeItem ? <activeItem.icon className="w-3.5 h-3.5" /> : <LayoutDashboard className="w-3.5 h-3.5" />}
            <span>{activeItem ? activeItem.label : 'Menu'}</span>
            <ChevronDown className={clsx('w-3.5 h-3.5 transition-transform duration-200', menuOpen && 'rotate-180')} />
          </button>

          {menuOpen && (
            <div className="fixed inset-0 z-20 bg-text-primary/10 sm:hidden" onClick={() => setMenuOpen(false)} />
          )}

          {menuOpen && (
            <div
              className={clsx(
                'absolute left-1/2 -translate-x-1/2 top-full mt-2 z-30',
                'w-[92vw] max-w-3xl bg-surface-1 border border-border rounded-xl shadow-popover',
                'animate-slide-up p-4 grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-5 max-h-[75vh] overflow-y-auto'
              )}
            >
              {navGroups.map((group) => {
                const items = group.items.filter((item) => !item.role || item.role === user?.role)
                if (items.length === 0) return null
                return (
                  <div key={group.label}>
                    <div className="section-label px-2 mb-1.5">
                      {group.label}
                    </div>
                    <div className="space-y-0.5">
                      {items.map((item) => (
                        <NavLink
                          key={item.path}
                          to={item.path}
                          className={({ isActive }) => clsx(
                            'flex items-center gap-2.5 px-2 py-1.5 rounded-md text-sm transition-colors',
                            isActive
                              ? 'bg-accent-cyan/10 text-accent-cyan font-medium'
                              : 'text-text-secondary hover:text-text-primary hover:bg-surface-2'
                          )}
                        >
                          <item.icon className="w-3.5 h-3.5 flex-shrink-0" />
                          <span className="truncate">{item.label}</span>
                        </NavLink>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="hidden md:block w-64 lg:w-80 xl:w-96">
            <GlobalSearch onOpen={openPalette} />
          </div>
          <button
            onClick={openPalette}
            className="md:hidden p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors"
            aria-label="Search"
          >
            <SearchIcon className="w-4 h-4" />
          </button>
          <NavLink to="/alerts" className="relative p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors">
            <Bell className="w-4 h-4" />
          </NavLink>
          <button
            onClick={openHelp}
            aria-label="Help"
            title="Help"
            className="p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors"
          >
            <HelpCircle className="w-4 h-4" />
          </button>
          <NavLink to="/settings" className="p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors">
            <Settings className="w-4 h-4" />
          </NavLink>
          <div className="hidden sm:flex items-center gap-2 pl-3 ml-1 border-l border-border">
            <div className="flex-shrink-0 w-7 h-7 rounded-full bg-accent-purple/15 border border-accent-purple/30 flex items-center justify-center text-xs font-semibold text-accent-purple">
              {user?.first_name?.[0]}{user?.last_name?.[0]}
            </div>
            <button
              onClick={handleLogout}
              className="flex-shrink-0 p-1.5 text-text-muted hover:text-accent-red hover:bg-accent-red/10 transition-colors rounded-md"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <HelpPanel open={helpOpen} onClose={() => setHelpOpen(false)} />
      <OnboardingTutorial />
    </div>
  )
}
