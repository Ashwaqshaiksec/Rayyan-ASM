import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  X, ArrowRight, ArrowLeft, Radar, Globe, Telescope, Scan, Bug, FileText, FlaskConical,
} from 'lucide-react'
import clsx from 'clsx'
import { useAuthStore } from '@/store/auth'
import { OPEN_TUTORIAL_EVENT } from './onboardingTutorial.utils'

const STORAGE_PREFIX = 'rayyan_tutorial_seen:'

/** Whether the current user has already dismissed or completed the tutorial. */
function hasSeenTutorial(userId: string): boolean {
  try {
    return localStorage.getItem(STORAGE_PREFIX + userId) === '1'
  } catch {
    return false
  }
}

function markTutorialSeen(userId: string) {
  try {
    localStorage.setItem(STORAGE_PREFIX + userId, '1')
  } catch {
    // localStorage unavailable (private browsing, etc) — not worth surfacing
  }
}

interface Step {
  icon: typeof Radar
  title: string
  body: string
  cta?: { label: string; path: string }
}

const STEPS: Step[] = [
  {
    icon: Radar,
    title: 'Welcome to Rayyan ASM',
    body: 'Rayyan continuously discovers and monitors your organization\'s external attack surface — domains, hosts, services, and the findings that come from scanning them. This quick walkthrough covers the core workflow in under a minute.',
  },
  {
    icon: Globe,
    title: 'Add your first domain',
    body: 'Everything starts with a domain. Add one under Assets → Domains, and Rayyan will use it as a seed for subdomain enumeration, DNS resolution, and certificate tracking.',
    cta: { label: 'Go to Domains', path: '/domains' },
  },
  {
    icon: Telescope,
    title: 'Run external discovery',
    body: 'External Discovery takes your seed domains and finds what\'s actually exposed — subdomains, IPs, open ports, and technologies — on a schedule you control.',
    cta: { label: 'Go to Discovery', path: '/discovery' },
  },
  {
    icon: Scan,
    title: 'Kick off a scan',
    body: 'Scans run the actual tool pipeline (subdomain enum, port scanning, vuln checks, and more) against your assets. Track progress and results from the Scans page.',
    cta: { label: 'Go to Scans', path: '/scans' },
  },
  {
    icon: Bug,
    title: 'Triage findings',
    body: 'Every issue a scan turns up lands in Findings, with severity, CVE/CVSS data where available, and a status you can move through acknowledged → fixed (or mark as a false positive).',
    cta: { label: 'Go to Findings', path: '/findings' },
  },
  {
    icon: FlaskConical,
    title: 'Quick one-off lookups',
    body: 'Need a fast answer without a full scan? The Toolbox has on-demand WHOIS, port scanning, TLS checks, CMS detection, and GeoIP — no scan job required.',
    cta: { label: 'Go to Toolbox', path: '/toolbox' },
  },
  {
    icon: FileText,
    title: 'You\'re set',
    body: 'Reports, SLA tracking, risk scoring, and attack-path analysis are all built on the same data as you go. You can replay this walkthrough any time from the help icon in the top bar.',
  },
]

export default function OnboardingTutorial() {
  const { user } = useAuthStore()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)

  useEffect(() => {
    if (user && !hasSeenTutorial(user.id)) setOpen(true)
  }, [user])

  // Exposes a way for other components (the header help button) to relaunch
  // the walkthrough without duplicating this modal's state.
  useEffect(() => {
    const openHandler = () => { setStep(0); setOpen(true) }
    window.addEventListener(OPEN_TUTORIAL_EVENT, openHandler)
    return () => window.removeEventListener(OPEN_TUTORIAL_EVENT, openHandler)
  }, [])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
      if (e.key === 'ArrowRight') next()
      if (e.key === 'ArrowLeft') back()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, step])

  if (!open) return null

  const close = () => {
    if (user) markTutorialSeen(user.id)
    setOpen(false)
  }

  const next = () => {
    if (step < STEPS.length - 1) setStep((s) => s + 1)
    else close()
  }

  const back = () => setStep((s) => Math.max(0, s - 1))

  const current = STEPS[step]
  const isLast = step === STEPS.length - 1

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-text-primary/20 backdrop-blur-sm" onClick={close} />

      <div className="relative w-full max-w-md bg-surface-1 border border-border rounded-xl shadow-popover animate-slide-up overflow-hidden">
        <button
          onClick={close}
          aria-label="Close tutorial"
          className="absolute top-3 right-3 p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="p-6 pt-8">
          <div className="reticle w-11 h-11 bg-surface-2 border border-border flex items-center justify-center mb-4">
            <current.icon className="w-5 h-5 text-accent-cyan" />
          </div>

          <h2 className="text-base font-semibold text-text-primary mb-2">{current.title}</h2>
          <p className="text-sm text-text-secondary leading-relaxed">{current.body}</p>

          {current.cta && (
            <button
              onClick={() => { navigate(current.cta!.path); close() }}
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-accent-cyan hover:underline"
            >
              {current.cta.label}
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>

        <div className="flex items-center justify-between px-6 py-3.5 border-t border-border-muted bg-surface-0/40">
          <div className="flex items-center gap-1.5">
            {STEPS.map((_, i) => (
              <span
                key={i}
                className={clsx(
                  'w-1.5 h-1.5 rounded-full transition-colors',
                  i === step ? 'bg-accent-cyan' : 'bg-border'
                )}
              />
            ))}
          </div>

          <div className="flex items-center gap-2">
            {step > 0 && (
              <button
                onClick={back}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-text-secondary hover:text-text-primary rounded-md hover:bg-surface-2 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back
              </button>
            )}
            {!isLast && (
              <button
                onClick={close}
                className="px-2.5 py-1.5 text-xs text-text-muted hover:text-text-primary rounded-md hover:bg-surface-2 transition-colors"
              >
                Skip
              </button>
            )}
            <button
              onClick={next}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/40 rounded-md hover:bg-accent-cyan/20 transition-colors"
            >
              {isLast ? 'Finish' : 'Next'}
              {!isLast && <ArrowRight className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
