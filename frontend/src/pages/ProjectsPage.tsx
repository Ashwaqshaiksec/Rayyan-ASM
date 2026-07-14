import { useState, useEffect, useCallback } from 'react'
import toast from 'react-hot-toast'
import api from '@/utils/api'
import {
  FolderOpen, Plus, Trash2, StickyNote, CheckSquare,
  ChevronDown, ChevronRight, Tag, Calendar, AlertCircle,
  CheckCircle2, Circle, Clock, Pencil, X, Check, AlertTriangle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface Project {
  id: string
  name: string
  slug: string
  description: string
  type: string
  color: string
  active: boolean
  created_at: string
}

interface Note {
  id: string
  project_id?: string
  title: string
  content: string
  target: string
  tags: string[]
  pinned: boolean
  created_at: string
}

interface Todo {
  id: string
  project_id?: string
  title: string
  notes: string
  status: string   // open | in_progress | done
  priority: string // low | medium | high | critical
  target: string
  due_at?: string
  created_at: string
}

// ── Helpers ────────────────────────────────────────────────────────────────

const PRIORITY_COLORS: Record<string, string> = {
  low: 'text-text-muted border-border',
  medium: 'text-accent-cyan border-accent-cyan/40',
  high: 'text-accent-orange border-accent-orange/40',
  critical: 'text-accent-red border-accent-red/40',
}

const STATUS_ICON: Record<string, JSX.Element> = {
  open: <Circle className="w-4 h-4 text-text-muted" />,
  in_progress: <Clock className="w-4 h-4 text-accent-cyan" />,
  done: <CheckCircle2 className="w-4 h-4 text-accent-green" />,
}

function fmtDate(iso?: string) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function LoadError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <AlertTriangle className="w-5 h-5 text-accent-orange" />
      <p className="text-sm text-text-muted">{message}</p>
      <button onClick={onRetry} className="text-xs text-accent-cyan hover:underline">Retry</button>
    </div>
  )
}

// ── Inline editable text ──────────────────────────────────────────────────

function InlineEdit({ value, onSave, className = '' }: {
  value: string
  onSave: (v: string) => void
  className?: string
}) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(value)
  const commit = () => { if (draft.trim()) onSave(draft.trim()); setEditing(false) }
  if (editing) {
    return (
      <div className="flex items-center gap-1">
        <input
          autoFocus
          className="bg-surface-2 border border-border rounded-md px-2 py-0.5 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') setEditing(false) }}
        />
        <button onClick={commit} className="text-accent-cyan hover:opacity-80"><Check className="w-3.5 h-3.5" /></button>
        <button onClick={() => setEditing(false)} className="text-text-muted hover:opacity-80"><X className="w-3.5 h-3.5" /></button>
      </div>
    )
  }
  return (
    <span className={`group cursor-pointer ${className}`} onClick={() => { setDraft(value); setEditing(true) }}>
      {value}
      <Pencil className="w-3 h-3 ml-1 inline opacity-0 group-hover:opacity-40 transition-opacity" />
    </span>
  )
}

// ── Projects Panel ─────────────────────────────────────────────────────────

function ProjectsPanel({ selectedId, onSelect }: {
  selectedId: string | null
  onSelect: (id: string | null) => void
}) {
  const [projects, setProjects] = useState<Project[]>([])
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [newType, setNewType] = useState('general')
  const [newColor, setNewColor] = useState('#6366f1')
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  const load = useCallback(async () => {
    setLoadError(false)
    setLoading(true)
    try {
      const res = await api.get<{ data: Project[] }>('/projects')
      setProjects(res.data.data ?? [])
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const create = async () => {
    if (!newName.trim()) return
    try {
      await api.post('/projects', { name: newName.trim(), type: newType, color: newColor })
      setNewName(''); setCreating(false)
      toast.success('Project created')
      load()
    } catch {
      toast.error('Failed to create project')
    }
  }

  const remove = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Delete project and all its notes/tasks?')) return
    try {
      await api.delete(`/projects/${id}`)
      if (selectedId === id) onSelect(null)
      toast.success('Project deleted')
      load()
    } catch {
      toast.error('Failed to delete project')
    }
  }

  const rename = async (p: Project, name: string) => {
    try {
      await api.put(`/projects/${p.id}`, { ...p, name })
      toast.success('Project renamed')
      load()
    } catch {
      toast.error('Failed to rename project')
    }
  }

  if (loading) return <div className="text-xs text-text-muted px-1 py-2">Loading…</div>
  if (loadError) return <LoadError message="Could not load projects" onRetry={load} />

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 overflow-x-auto pb-1 -mb-1">
        <button
          onClick={() => onSelect(null)}
          className={`flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm border transition-colors ${
            selectedId === null
              ? 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 font-medium'
              : 'text-text-secondary border-border bg-surface-1 hover:bg-surface-2 hover:border-surface-4'
          }`}
        >
          <FolderOpen className="w-3.5 h-3.5" /> All
        </button>

        {projects.map(p => (
          <div
            key={p.id}
            onClick={() => onSelect(p.id)}
            className={`group flex-shrink-0 flex items-center gap-2 pl-3 pr-2 py-1.5 rounded-full text-sm border cursor-pointer transition-colors ${
              selectedId === p.id
                ? 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 font-medium'
                : 'text-text-secondary border-border bg-surface-1 hover:bg-surface-2 hover:border-surface-4'
            }`}
          >
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: p.color }} />
            <InlineEdit value={p.name} onSave={name => rename(p, name)} className="truncate max-w-[10rem]" />
            <button onClick={e => remove(p.id, e)} className="opacity-0 group-hover:opacity-60 hover:!opacity-100 text-accent-red transition-opacity flex-shrink-0">
              <Trash2 className="w-3 h-3" />
            </button>
          </div>
        ))}

        <button
          onClick={() => setCreating(true)}
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm border border-dashed border-border text-text-muted hover:text-accent-cyan hover:border-accent-cyan/40 hover:bg-accent-cyan/5 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" /> New project
        </button>
      </div>

      {creating && (
        <div className="p-3 bg-surface-1 border border-border rounded-xl shadow-card flex flex-col sm:flex-row gap-2 sm:items-center animate-fade-in">
          <input
            autoFocus
            placeholder="Project name"
            className="input flex-1"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') create(); if (e.key === 'Escape') setCreating(false) }}
          />
          <select
            className="input sm:w-40"
            value={newType}
            onChange={e => setNewType(e.target.value)}
          >
            {['general', 'bug_bounty', 'client', 'personal'].map(t => (
              <option key={t} value={t}>{t.replace('_', ' ')}</option>
            ))}
          </select>
          <input type="color" value={newColor} onChange={e => setNewColor(e.target.value)}
            className="h-8 w-10 rounded-lg border border-border bg-surface-1 cursor-pointer flex-shrink-0" />
          <div className="flex gap-2 flex-shrink-0">
            <button onClick={create} className="btn-primary flex-1 sm:flex-none">Create</button>
            <button onClick={() => setCreating(false)} className="btn-secondary flex-1 sm:flex-none">Cancel</button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Notes Panel ────────────────────────────────────────────────────────────

function NotesPanel({ projectId }: { projectId: string | null }) {
  const [notes, setNotes] = useState<Note[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ title: '', content: '', target: '', tags: '' })
  const [loadError, setLoadError] = useState(false)

  const load = useCallback(async () => {
    setLoadError(false)
    try {
      const params = projectId ? `?project_id=${projectId}` : ''
      const res = await api.get<{ data: Note[] }>(`/notes${params}`)
      setNotes(res.data.data ?? [])
    } catch {
      setLoadError(true)
    }
  }, [projectId])

  useEffect(() => { load() }, [load])

  const create = async () => {
    if (!form.title.trim()) return
    try {
      await api.post('/notes', {
        title: form.title.trim(),
        content: form.content,
        target: form.target,
        tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
        project_id: projectId ?? undefined,
      })
      setForm({ title: '', content: '', target: '', tags: '' })
      setCreating(false)
      toast.success('Note saved')
      load()
    } catch {
      toast.error('Failed to save note')
    }
  }

  const remove = async (id: string) => {
    if (!confirm('Delete note?')) return
    try {
      await api.delete(`/notes/${id}`)
      toast.success('Note deleted')
      load()
    } catch {
      toast.error('Failed to delete note')
    }
  }

  const togglePin = async (n: Note) => {
    try {
      await api.put(`/notes/${n.id}`, { ...n, pinned: !n.pinned })
      load()
    } catch {
      toast.error('Failed to update note')
    }
  }

  const sorted = [...notes].sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0))

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
          <StickyNote className="w-4 h-4 text-accent-yellow" /> Notes
          <span className="text-xs text-text-muted font-normal">({notes.length})</span>
        </h3>
        <button onClick={() => setCreating(v => !v)} className="flex items-center gap-1 text-xs text-accent-cyan hover:opacity-80 transition-opacity">
          <Plus className="w-3.5 h-3.5" /> Add
        </button>
      </div>

      {loadError && <LoadError message="Could not load notes" onRetry={load} />}

      {creating && (
        <div className="mb-4 p-3 bg-surface-2 border border-border rounded-lg flex flex-col gap-2">
          <input placeholder="Title *" className="input-sm" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          <textarea placeholder="Content" rows={3} className="input-sm resize-none" value={form.content} onChange={e => setForm(f => ({ ...f, content: e.target.value }))} />
          <input placeholder="Target (domain/IP)" className="input-sm" value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))} />
          <input placeholder="Tags (comma-separated)" className="input-sm" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} />
          <div className="flex gap-2">
            <button onClick={create} className="btn-primary-xs">Save</button>
            <button onClick={() => setCreating(false)} className="btn-ghost-xs">Cancel</button>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2">
        {sorted.length === 0 && !creating && !loadError && (
          <p className="text-xs text-text-muted text-center py-4">No notes yet. Add one above.</p>
        )}
        {sorted.map(n => (
          <div key={n.id} className={`border rounded-lg transition-colors ${n.pinned ? 'border-accent-yellow/40 bg-accent-yellow/5' : 'border-border bg-surface-2'}`}>
            <div
              className="flex items-center gap-2 px-3 py-2 cursor-pointer"
              onClick={() => setExpanded(expanded === n.id ? null : n.id)}
            >
              {expanded === n.id ? <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />}
              <span className="flex-1 text-sm text-text-primary truncate">{n.title}</span>
              {n.target && <span className="text-xs text-text-muted truncate max-w-[120px]">{n.target}</span>}
              {n.pinned && <span className="text-xs text-accent-yellow">📌</span>}
              <span className="text-xs text-text-muted ml-1">{fmtDate(n.created_at)}</span>
              <button onClick={e => { e.stopPropagation(); togglePin(n) }} className="p-1 text-text-muted hover:text-accent-yellow transition-colors flex-shrink-0">
                {n.pinned ? '📌' : '📍'}
              </button>
              <button onClick={e => { e.stopPropagation(); remove(n.id) }} className="p-1 text-text-muted hover:text-accent-red transition-colors flex-shrink-0">
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
            {expanded === n.id && (
              <div className="px-3 pb-3 border-t border-border-muted mt-1 pt-2">
                <p className="text-sm text-text-secondary whitespace-pre-wrap">{n.content || <em className="text-text-muted">No content</em>}</p>
                {n.tags?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {n.tags.map(t => (
                      <span key={t} className="flex items-center gap-0.5 px-1.5 py-0.5 bg-surface-3 border border-border rounded-md text-xs text-text-muted">
                        <Tag className="w-2.5 h-2.5" />{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Todos Panel ────────────────────────────────────────────────────────────

function TodosPanel({ projectId }: { projectId: string | null }) {
  const [todos, setTodos] = useState<Todo[]>([])
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ title: '', notes: '', priority: 'medium', target: '', due_at: '' })
  const [filter, setFilter] = useState<string>('open,in_progress')
  const [loadError, setLoadError] = useState(false)

  const load = useCallback(async () => {
    setLoadError(false)
    try {
      const params = projectId ? `?project_id=${projectId}` : ''
      const res = await api.get<{ data: Todo[] }>(`/todos${params}`)
      setTodos(res.data.data ?? [])
    } catch {
      setLoadError(true)
    }
  }, [projectId])

  useEffect(() => { load() }, [load])

  const create = async () => {
    if (!form.title.trim()) return
    try {
      await api.post('/todos', {
        title: form.title.trim(),
        notes: form.notes,
        priority: form.priority,
        target: form.target,
        due_at: form.due_at || undefined,
        project_id: projectId ?? undefined,
      })
      setForm({ title: '', notes: '', priority: 'medium', target: '', due_at: '' })
      setCreating(false)
      toast.success('Task created')
      load()
    } catch {
      toast.error('Failed to create task')
    }
  }

  const cycleStatus = async (t: Todo) => {
    const next = t.status === 'open' ? 'in_progress' : t.status === 'in_progress' ? 'done' : 'open'
    try {
      await api.put(`/todos/${t.id}`, { ...t, status: next })
      load()
    } catch {
      toast.error('Failed to update task status')
    }
  }

  const remove = async (id: string) => {
    if (!confirm('Delete task?')) return
    try {
      await api.delete(`/todos/${id}`)
      toast.success('Task deleted')
      load()
    } catch {
      toast.error('Failed to delete task')
    }
  }

  const filters = [
    { label: 'Active', value: 'open,in_progress' },
    { label: 'Done', value: 'done' },
    { label: 'All', value: '' },
  ]

  const visible = todos.filter(t => !filter || filter.split(',').includes(t.status))
  const counts = {
    open: todos.filter(t => t.status === 'open').length,
    in_progress: todos.filter(t => t.status === 'in_progress').length,
    done: todos.filter(t => t.status === 'done').length,
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
          <CheckSquare className="w-4 h-4 text-accent-purple" /> Tasks
          <span className="text-xs text-text-muted font-normal">
            {counts.open} open · {counts.in_progress} in progress · {counts.done} done
          </span>
        </h3>
        <button onClick={() => setCreating(v => !v)} className="flex items-center gap-1 text-xs text-accent-cyan hover:opacity-80 transition-opacity">
          <Plus className="w-3.5 h-3.5" /> Add
        </button>
      </div>

      <div className="flex gap-1 mb-3">
        {filters.map(f => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`px-2.5 py-1 rounded-md text-xs transition-colors ${filter === f.value ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30' : 'text-text-muted hover:text-text-primary border border-transparent'}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {loadError && <LoadError message="Could not load tasks" onRetry={load} />}

      {creating && (
        <div className="mb-4 p-3 bg-surface-2 border border-border rounded-lg flex flex-col gap-2">
          <input placeholder="Task title *" className="input-sm" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          <div className="flex gap-2">
            <select className="flex-1 input-sm" value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}>
              {['low', 'medium', 'high', 'critical'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <input type="date" className="flex-1 input-sm" value={form.due_at} onChange={e => setForm(f => ({ ...f, due_at: e.target.value }))} />
          </div>
          <input placeholder="Target (domain/IP)" className="input-sm" value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))} />
          <textarea placeholder="Notes" rows={2} className="input-sm resize-none" value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} />
          <div className="flex gap-2">
            <button onClick={create} className="btn-primary-xs">Save</button>
            <button onClick={() => setCreating(false)} className="btn-ghost-xs">Cancel</button>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-1.5">
        {visible.length === 0 && !creating && !loadError && (
          <p className="text-xs text-text-muted text-center py-4">No tasks here.</p>
        )}
        {visible.map(t => (
          <div key={t.id} className={`flex items-start gap-2.5 px-3 py-2 bg-surface-2 border rounded-lg transition-colors ${t.status === 'done' ? 'opacity-50 border-border' : 'border-border'}`}>
            <button onClick={() => cycleStatus(t)} className="flex-shrink-0 mt-0.5" title="Cycle status">
              {STATUS_ICON[t.status]}
            </button>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-sm ${t.status === 'done' ? 'line-through text-text-muted' : 'text-text-primary'}`}>{t.title}</span>
                <span className={`text-[10px] px-1.5 py-0.5 border rounded-md font-medium ${PRIORITY_COLORS[t.priority] ?? ''}`}>{t.priority}</span>
                {t.target && <span className="text-xs text-text-muted truncate max-w-[100px]">{t.target}</span>}
              </div>
              {t.notes && <p className="text-xs text-text-muted mt-0.5 truncate">{t.notes}</p>}
              {t.due_at && (
                <p className={`text-xs flex items-center gap-1 mt-0.5 ${new Date(t.due_at) < new Date() && t.status !== 'done' ? 'text-accent-red' : 'text-text-muted'}`}>
                  {new Date(t.due_at) < new Date() && t.status !== 'done' ? <AlertCircle className="w-3 h-3" /> : <Calendar className="w-3 h-3" />}
                  Due {fmtDate(t.due_at)}
                </p>
              )}
            </div>
            <button onClick={() => remove(t.id)} className="flex-shrink-0 text-text-muted hover:text-accent-red transition-colors">
              <Trash2 className="w-3 h-3" />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────

export default function ProjectsPage() {
  const [selectedProject, setSelectedProject] = useState<string | null>(null)

  return (
    <main className="h-full overflow-y-auto p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2 mb-1">
          <FolderOpen className="w-5 h-5 text-accent-cyan" />
          {selectedProject ? 'Project' : 'All'} — Projects
        </h1>
        <p className="text-sm text-text-muted">Organise recon notes and tasks.</p>
      </div>

      <ProjectsPanel selectedId={selectedProject} onSelect={setSelectedProject} />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="card p-5">
          <NotesPanel projectId={selectedProject} />
        </section>
        <section className="card p-5">
          <TodosPanel projectId={selectedProject} />
        </section>
      </div>
    </main>
  )
}
