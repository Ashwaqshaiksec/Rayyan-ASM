import { useState } from 'react'
import { X, Scan, ChevronDown, Info } from 'lucide-react'
import clsx from 'clsx'
import { isAxiosError } from 'axios'

// Mirror of workflowStages in workflows.go — kept in sync manually.

type WorkflowId =
  | ''
  | 'external_asm'
  | 'bug_bounty'
  | 'internal_assessment'
  | 'dns_assessment'
  | 'web_assessment'
  | 'web_full'
  | 'api_audit'
  | 'js_recon'
  | 'cms_detect'
  | 'injection_suite'
  | 'git_secrets'
  | 'takeover_scan'
  | 'nuclei_full_scan'
  | 'screenshot'
  | 'cloud_enum'

interface WorkflowDef {
  id:          WorkflowId
  label:       string
  description: string
  stages:      string[]
}

const WORKFLOWS: WorkflowDef[] = [
  {
    id:          '',
    label:       'None (manual)',
    description: 'Run a single scan type without a predefined tool chain.',
    stages:      [],
  },
  {
    id:          'external_asm',
    label:       'External ASM',
    description: 'Full external attack-surface mapping — subdomains → DNS → ports → web → crawl → content → vulns.',
    stages:      ['subdomain', 'dns', 'network', 'web (probe)', 'web (crawl)', 'content', 'vulnerability'],
  },
  {
    id:          'bug_bounty',
    label:       'Bug Bounty',
    description: 'Optimised for bug-bounty scopes — subdomains → DNS → web → crawl → content → vulns.',
    stages:      ['subdomain', 'dns', 'web (probe)', 'web (crawl)', 'content', 'vulnerability'],
  },
  {
    id:          'internal_assessment',
    label:       'Internal Assessment',
    description: 'Internal network sweep — port scan → SMB enumeration → vulnerability scan.',
    stages:      ['network', 'smb', 'vulnerability'],
  },
  {
    id:          'dns_assessment',
    label:       'DNS Assessment',
    description: 'Focused DNS-only analysis — zone enumeration, typo-squatting, record mapping.',
    stages:      ['dns'],
  },
  {
    id:          'web_assessment',
    label:       'Web Assessment',
    description: 'Targeted web analysis — HTTP probing → content discovery → vulnerability scan.',
    stages:      ['web (probe)', 'content', 'vulnerability'],
  },
  {
    id:          'web_full',
    label:       'Web Full',
    description: 'Deep web assessment — probe → crawl → content → fingerprint → params → injection → vulns → JS analysis.',
    stages:      ['web (probe)', 'web (crawl)', 'content', 'fingerprint', 'params', 'injection', 'vulnerability', 'js_analysis'],
  },
  {
    id:          'api_audit',
    label:       'API Audit',
    description: 'REST/GraphQL API assessment — endpoint discovery → parameter mining → auth checks → injection.',
    stages:      ['content', 'params', 'auth', 'injection', 'vulnerability'],
  },
  {
    id:          'js_recon',
    label:       'JS Recon',
    description: 'JavaScript analysis — extract endpoints, secrets, and vulnerable library versions.',
    stages:      ['js_analysis'],
  },
  {
    id:          'cms_detect',
    label:       'CMS Detect',
    description: 'Fingerprint the CMS then run targeted CMS vulnerability scanners (wpscan / droopescan).',
    stages:      ['fingerprint', 'vulnerability'],
  },
  {
    id:          'injection_suite',
    label:       'Injection Suite',
    description: 'Runs all injection tools in priority order — SQLi, XSS, SSTI, CRLF, request smuggling, SSRF.',
    stages:      ['injection'],
  },
  {
    id:          'git_secrets',
    label:       'Git Secrets',
    description: 'Scan a Git repository URL for secrets and credentials — trufflehog → gitleaks.',
    stages:      ['secrets'],
  },
  {
    id:          'takeover_scan',
    label:       'Takeover Scan',
    description: 'Enumerate subdomains then check every discovered host for subdomain takeover vulnerability.',
    stages:      ['subdomain', 'dns', 'takeover'],
  },
  {
    id:          'nuclei_full_scan',
    label:       'Nuclei Full Scan',
    description: 'Run the complete Nuclei template library against the target after probing live hosts.',
    stages:      ['web (probe)', 'fingerprint', 'vulnerability'],
  },
  {
    id:          'screenshot',
    label:       'Screenshot',
    description: 'Probe live HTTP hosts then capture screenshots with gowitness and aquatone.',
    stages:      ['web (probe)', 'screenshot'],
  },
  {
    id:          'cloud_enum',
    label:       'Cloud Enum',
    description: 'Enumerate cloud resources via native CLI tools (aws / az / gcloud). Credentials must be pre-configured.',
    stages:      ['cloud'],
  },
]


const SCAN_TYPES = ['full', 'network', 'port', 'dns', 'web'] as const
type ScanType = typeof SCAN_TYPES[number]


interface NewScanModalProps {
  onClose:  () => void
  onSubmit: (payload: {
    target:   string
    type:     string
    workflow: string
  }) => Promise<void>
}


export default function NewScanModal({ onClose, onSubmit }: NewScanModalProps) {
  const [target,   setTarget]   = useState('')
  const [type,     setType]     = useState<ScanType>('full')
  const [workflow, setWorkflow] = useState<WorkflowId>('')
  const [submitting, setSubmitting] = useState(false)
  const [error,    setError]    = useState('')

  const selectedWorkflow = WORKFLOWS.find(w => w.id === workflow)!

  const handleSubmit = async () => {
    const t = target.trim()
    if (!t) { setError('Target is required'); return }
    setError('')
    setSubmitting(true)
    try {
      await onSubmit({ target: t, type, workflow })
      onClose()
    } catch (e) {
      const message = isAxiosError<{ error: string }>(e)
        ? e.response?.data?.error
        : undefined
      setError(message ?? 'Failed to create scan')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-lg bg-surface-1 border border-border rounded-xl shadow-popover animate-fade-in">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <h2 className="text-base font-semibold text-text-primary flex items-center gap-2">
            <Scan className="w-4 h-4 text-accent-cyan" />
            New Scan
          </h2>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-surface-2 text-text-muted hover:text-text-primary transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
              Target
            </label>
            <input
              type="text"
              placeholder="example.com or 10.0.0.0/24"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="input"
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
              Scan Type
            </label>
            <div className="flex flex-wrap gap-1.5">
              {SCAN_TYPES.map(st => (
                <button
                  key={st}
                  onClick={() => setType(st)}
                  className={clsx(
                    'px-3 py-1 rounded-md text-xs font-medium border transition-colors capitalize',
                    type === st
                      ? 'bg-accent-cyan/10 border-accent-cyan/40 text-accent-cyan'
                      : 'bg-surface-2 border-border text-text-muted hover:text-text-secondary'
                  )}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide flex items-center gap-1">
              Workflow
              <span className="text-text-muted font-normal normal-case tracking-normal">(optional tool chain)</span>
            </label>
            <div className="relative">
              <select
                value={workflow}
                onChange={e => setWorkflow(e.target.value as WorkflowId)}
                className="input appearance-none pr-8"
              >
                {WORKFLOWS.map(w => (
                  <option key={w.id} value={w.id}>{w.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
            </div>

            {selectedWorkflow && (
              <div className="bg-surface-2/60 border border-border rounded-lg p-3 space-y-2">
                <p className="text-xs text-text-muted">{selectedWorkflow.description}</p>
                {selectedWorkflow.stages.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {selectedWorkflow.stages.map((s, i) => (
                      <span key={i} className="flex items-center gap-1">
                        {i > 0 && <span className="text-text-muted text-xs">→</span>}
                        <span className="px-1.5 py-0.5 rounded-md text-xs bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
                          {s}
                        </span>
                      </span>
                    ))}
                  </div>
                )}
                {workflow !== '' && (
                  <div className="flex items-start gap-1.5 text-xs text-text-muted">
                    <Info className="w-3 h-3 flex-shrink-0 mt-0.5 text-accent-cyan" />
                    Tool selection within each stage is automatic: the first installed
                    and enabled tool for the category will be used.
                  </div>
                )}
              </div>
            )}
          </div>

          {type === 'full' && workflow === '' && (
            <div className="flex items-start gap-1.5 text-xs text-accent-orange bg-accent-orange/10 border border-accent-orange/20 rounded-md px-3 py-2">
              <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>
                Full scan covers network → subdomain → port → dns → web only.
                Cloud Assets, Subdomain Takeover, and Technologies come from a
                separate Workflow (e.g. Cloud Enum, Takeover Scan) — pick one
                above if you want those populated too.
              </span>
            </div>
          )}

          {error && (
            <p className="text-xs text-accent-red bg-accent-red/10 border border-accent-red/20 rounded-md px-3 py-2">
              {error}
            </p>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border">
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !target.trim()}
            className="btn-primary inline-flex items-center gap-1.5"
          >
            {submitting
              ? <><div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Starting…</>
              : <><Scan className="w-3.5 h-3.5" /> Start Scan</>
            }
          </button>
        </div>
      </div>
    </div>
  )
}
