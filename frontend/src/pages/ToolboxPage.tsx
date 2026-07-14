import { useState } from 'react'
import {
  Globe, Shield, MapPin, Search, Terminal,
  AlertTriangle, CheckCircle, XCircle, Info, Lock, Loader2
} from 'lucide-react'
import { toolboxApi } from '@/utils/api'
import { WHOISHistoryWidget } from '@/components/WHOISHistoryWidget'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { format } from 'date-fns'


type Tab = 'whois' | 'ports' | 'cms' | 'tls' | 'geoip' | 'cve'

// WHOIS / CMS results are free-form key-value records from their
// respective backend probes — shape varies per target, so a record of
// unknown values (rather than `any`) is the honest type.
type ToolboxRecord = Record<string, unknown>

interface TLSVersionResult {
  supported: boolean
  cipher?: string
  error?: string
}

interface TLSCertInfo {
  subject: string
  issuer: string
  sans: string[]
  not_before: string
  not_after: string
  days_remaining: number
  expired: boolean
  self_signed: boolean
  sig_algorithm: string
}

interface TLSCheckResult {
  target: string
  host: string
  port: string
  negotiated_version: string
  negotiated_cipher: string
  version_support: Record<string, TLSVersionResult>
  certificate_chain: TLSCertInfo[]
  issues: string[]
  issues_count: number
}

// GeoIP proxies ip-api.com's response as-is — an external, loosely-typed payload.
interface GeoIPData {
  country?: string
  countryCode?: string
  region?: string
  regionName?: string
  city?: string
  zip?: string
  lat?: number
  lon?: number
  timezone?: string
  isp?: string
  org?: string
  as?: string
  asname?: string
  reverse?: string
  mobile?: boolean
  proxy?: boolean
  hosting?: boolean
}
interface GeoIPResult {
  ip: string
  data?: GeoIPData
}

// CVE proxies the NVD CVE 2.0 API response as-is (or { raw } on parse failure).
interface NVDCVSSData {
  baseScore?: number
  baseSeverity?: string
}
interface NVDCVE {
  id: string
  published: string
  lastModified: string
  descriptions?: { lang: string; value: string }[]
  metrics?: {
    cvssMetricV31?: { cvssData: NVDCVSSData }[]
    cvssMetricV30?: { cvssData: NVDCVSSData }[]
    cvssMetricV2?: { cvssData: NVDCVSSData & { vectorString?: string } }[]
  }
  references?: { url: string }[]
}
interface CVELookupResult {
  cve_id: string
  data?: { vulnerabilities?: { cve: NVDCVE }[] }
  raw?: string
}


function KV({ label, value }: { label: string; value?: string | number | boolean | null }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="grid grid-cols-3 gap-2 py-1.5 border-b border-border/50 last:border-0">
      <span className="text-xs text-text-muted col-span-1 font-medium">{label}</span>
      <span className="text-xs text-text-primary col-span-2 font-mono break-all">{String(value)}</span>
    </div>
  )
}

function Section({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card p-4 space-y-1">
      <div className="flex items-center gap-2 mb-2 pb-2 border-b border-border">
        {icon}
        <span className="text-sm font-semibold text-text-primary">{title}</span>
      </div>
      {children}
    </div>
  )
}

function InputRow({
  label, placeholder, value, onChange, onSubmit, loading, children
}: {
  label: string
  placeholder: string
  value: string
  onChange: (v: string) => void
  onSubmit: () => void
  loading: boolean
  children?: React.ReactNode
}) {
  return (
    <div className="card p-4 flex flex-col sm:flex-row gap-3 items-end">
      <div className="flex-1">
        <label className="text-xs text-text-muted mb-1 block">{label}</label>
        <input
          className="input w-full"
          placeholder={placeholder}
          value={value}
          onChange={e => onChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onSubmit()}
        />
        {children}
      </div>
      <button
        className="btn-primary flex items-center gap-2 shrink-0"
        onClick={onSubmit}
        disabled={loading || !value.trim()}
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
        {loading ? 'Checking…' : 'Run'}
      </button>
    </div>
  )
}


function WhoisTab() {
  const [domain, setDomain] = useState('')
  const [result, setResult] = useState<ToolboxRecord | null>(null)
  const [showRaw, setShowRaw] = useState(false)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    if (!domain.trim()) return
    setLoading(true); setResult(null); setShowRaw(false)
    try {
      const { data } = await toolboxApi.whois(domain.trim())
      setResult(data)
    } catch { toast.error('WHOIS lookup failed') }
    finally { setLoading(false) }
  }

  // Two response shapes from the backend: a successful RDAP lookup
  // (source: 'rdap', structured fields) or the system-whois fallback
  // (source: 'whois_fallback', plain-text 'output' — used for IP targets
  // and the handful of ccTLDs with no public RDAP server).
  const isRDAP = result?.source === 'rdap'
  const nameservers = Array.isArray(result?.nameservers) ? result.nameservers as string[] : []
  const output = typeof result?.output === 'string' ? result.output : undefined
  const err = typeof result?.error === 'string' ? result.error : undefined

  return (
    <div className="space-y-4">
      <InputRow label="Domain name" placeholder="example.com" value={domain} onChange={setDomain} onSubmit={run} loading={loading} />
      {result && isRDAP && (
        <Section title="WHOIS Result (RDAP)" icon={<Globe className="w-4 h-4 text-accent-cyan" />}>
          <KV label="Registrar" value={result.registrar as string} />
          <KV label="Registrar IANA ID" value={result.registrar_iana_id as string} />
          <KV label="Registered" value={result.registration_date as string} />
          <KV label="Expires" value={result.expiry_date as string} />
          <KV label="Last Updated" value={result.updated_date as string} />
          {nameservers.length > 0 && (
            <div className="grid grid-cols-3 gap-2 py-1.5 border-b border-border/50 last:border-0">
              <span className="text-xs text-text-muted col-span-1 font-medium">Nameservers</span>
              <div className="col-span-2 space-y-0.5">
                {nameservers.map(ns => <div key={ns} className="text-xs text-text-primary font-mono">{ns}</div>)}
              </div>
            </div>
          )}
          <button
            className="text-xs text-accent-cyan hover:underline mt-2"
            onClick={() => setShowRaw(v => !v)}
          >
            {showRaw ? 'Hide raw RDAP response' : 'Show raw RDAP response'}
          </button>
          {showRaw && typeof result.raw === 'string' && (
            <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto mt-2">
              {(() => { try { return JSON.stringify(JSON.parse(result.raw as string), null, 2) } catch { return result.raw as string } })()}
            </pre>
          )}
        </Section>
      )}
      {result && !isRDAP && (
        <Section title="WHOIS Result" icon={<Globe className="w-4 h-4 text-accent-cyan" />}>
          {output
            ? <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap leading-relaxed">{output}</pre>
            : <p className="text-xs text-accent-red">{err ?? 'No WHOIS data found for this target.'}</p>
          }
        </Section>
      )}
      {domain.trim() && (
        <Section title="WHOIS History" icon={<Globe className="w-4 h-4 text-accent-purple" />}>
          <WHOISHistoryWidget domain={domain.trim()} />
        </Section>
      )}
    </div>
  )
}


interface PortScanResult {
  target: string
  profile: string
  ports_probed: number
  open_ports: { port: number; service: string; banner?: string; latency: string }[]
  open_count: number
}

function PortScanTab() {
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState<'quick' | 'top100'>('quick')
  const [result, setResult] = useState<PortScanResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    if (!target.trim()) return
    setLoading(true); setResult(null)
    try {
      const { data } = await toolboxApi.portScan(target.trim(), profile)
      setResult(data)
    } catch { toast.error('Port scan failed') }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-4">
      <InputRow label="Host or IP" placeholder="example.com or 1.2.3.4" value={target} onChange={setTarget} onSubmit={run} loading={loading}>
        <div className="flex gap-1 mt-2">
          {(['quick', 'top100'] as const).map(p => (
            <button
              key={p}
              type="button"
              onClick={() => setProfile(p)}
              className={clsx(
                'px-2 py-0.5 rounded text-xs font-medium border',
                profile === p ? 'bg-surface-3 border-border text-text-primary' : 'border-border/50 text-text-muted hover:text-text-primary'
              )}
            >
              {p === 'quick' ? 'Common ports' : 'Top 100'}
            </button>
          ))}
        </div>
      </InputRow>
      {result && (
        <Section title={`Open Ports — ${result.target}`} icon={<Terminal className="w-4 h-4 text-accent-cyan" />}>
          <p className="text-xs text-text-muted mb-2">
            Probed {result.ports_probed} ports, found {result.open_count} open.
          </p>
          {result.open_ports.length === 0 ? (
            <p className="text-xs text-text-muted">No open ports found in this profile.</p>
          ) : (
            <div className="space-y-1">
              {result.open_ports.map(p => (
                <div key={p.port} className="grid grid-cols-4 gap-2 py-1.5 border-b border-border/50 last:border-0 text-xs">
                  <span className="font-mono text-text-primary">{p.port}/tcp</span>
                  <span className="text-accent-cyan">{p.service}</span>
                  <span className="text-text-muted col-span-2 truncate font-mono">{p.banner ?? ''}</span>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}
    </div>
  )
}


function CMSTab() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<ToolboxRecord | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    if (!url.trim()) return
    setLoading(true); setResult(null)
    try {
      const { data } = await toolboxApi.cmsDetect(url.trim())
      setResult(data)
    } catch { toast.error('CMS detection failed') }
    finally { setLoading(false) }
  }

  // Backend returns either { target, results: [...whatweb plugin hits...] }
  // or, on whatweb failure, { target, raw, error }. There is no flat
  // cms/version/confidence/indicators field — render what's actually sent.
  const results = Array.isArray(result?.results) ? result.results : []
  const raw = typeof result?.raw === 'string' ? result.raw : undefined
  const detectError = typeof result?.error === 'string' ? result.error : undefined

  return (
    <div className="space-y-4">
      <InputRow label="Target URL" placeholder="https://example.com" value={url} onChange={setUrl} onSubmit={run} loading={loading} />
      {result && (
        <Section title="CMS Detection" icon={<Terminal className="w-4 h-4 text-accent-cyan" />}>
          {results.length > 0 ? (
            <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
              {JSON.stringify(results, null, 2)}
            </pre>
          ) : raw ? (
            <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">{raw}</pre>
          ) : (
            <p className="text-xs text-text-muted">No technology fingerprints detected.</p>
          )}
          {detectError && <p className="text-xs text-accent-red mt-2">whatweb error: {detectError}</p>}
        </Section>
      )}
    </div>
  )
}


function TLSTab() {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<TLSCheckResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    if (!target.trim()) return
    setLoading(true); setResult(null)
    try {
      const { data } = await toolboxApi.tlsCheck(target.trim())
      setResult(data)
    } catch { toast.error('TLS check failed') }
    finally { setLoading(false) }
  }

  const versionBadge = (name: string, info: TLSVersionResult) => {
    const deprecated = name === 'TLSv1.0' || name === 'TLSv1.1'
    if (!info.supported) return (
      <div key={name} className="flex items-center gap-2 py-1">
        <XCircle className="w-3.5 h-3.5 text-text-muted" />
        <span className="text-xs text-text-muted">{name}</span>
        <span className="text-xs text-text-muted ml-auto">Not supported</span>
      </div>
    )
    return (
      <div key={name} className={clsx('flex items-center gap-2 py-1 rounded-md px-2', deprecated ? 'bg-accent-red/5' : '')}>
        {deprecated
          ? <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />
          : <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
        }
        <span className={clsx('text-xs font-medium', deprecated ? 'text-accent-red' : 'text-text-primary')}>{name}</span>
        {deprecated && <span className="text-[10px] text-accent-red bg-accent-red/10 border border-accent-red/30 rounded-md px-1">DEPRECATED</span>}
        <span className="text-xs text-text-muted ml-auto font-mono">{info.cipher}</span>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <InputRow label="Host or host:port" placeholder="example.com  or  example.com:8443" value={target} onChange={setTarget} onSubmit={run} loading={loading} />
      {result && (
        <div className="space-y-4">
          {/* Issues banner */}
          {result.issues_count > 0 && (
            <div className="card p-4 border-accent-red/20 bg-accent-red/5 space-y-1">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-accent-red" />
                <span className="text-sm font-semibold text-accent-red">{result.issues_count} Issue{result.issues_count !== 1 ? 's' : ''} Found</span>
              </div>
              {result.issues.map((iss: string, i: number) => (
                <p key={i} className="text-xs text-accent-red pl-6">• {iss}</p>
              ))}
            </div>
          )}
          {result.issues_count === 0 && (
            <div className="card p-3 border-accent-green/20 bg-accent-green/5 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-accent-green" />
              <span className="text-sm text-accent-green">No TLS issues detected</span>
            </div>
          )}

          {/* Negotiated */}
          <Section title="Negotiated Session" icon={<Lock className="w-4 h-4 text-accent-cyan" />}>
            <KV label="Version" value={result.negotiated_version} />
            <KV label="Cipher suite" value={result.negotiated_cipher} />
          </Section>

          {/* Version support */}
          <Section title="Protocol Support" icon={<Shield className="w-4 h-4 text-accent-cyan" />}>
            {Object.entries(result.version_support ?? {})
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([name, info]) => versionBadge(name, info))}
          </Section>

          {/* Certificate chain */}
          {(result.certificate_chain ?? []).length > 0 && (
            <Section title="Certificate Chain" icon={<Lock className="w-4 h-4 text-accent-cyan" />}>
              {result.certificate_chain.map((cert: TLSCertInfo, i: number) => (
                <div key={i} className="mb-3 last:mb-0">
                  {i > 0 && <div className="border-t border-border my-2" />}
                  <p className="text-xs text-text-muted mb-1 font-semibold">#{i + 1}</p>
                  <KV label="Subject" value={cert.subject} />
                  <KV label="Issuer" value={cert.issuer} />
                  <KV label="SANs" value={(cert.sans ?? []).slice(0, 5).join(', ')} />
                  <KV label="Not before" value={cert.not_before ? format(new Date(cert.not_before), 'yyyy-MM-dd HH:mm') : ''} />
                  <KV label="Not after" value={cert.not_after ? format(new Date(cert.not_after), 'yyyy-MM-dd HH:mm') : ''} />
                  <div className="flex gap-2 mt-1">
                    {cert.expired && <span className="text-[10px] bg-accent-red/10 text-accent-red border border-accent-red/30 rounded-md px-1.5 py-0.5">EXPIRED</span>}
                    {!cert.expired && cert.days_remaining < 30 && (
                      <span className="text-[10px] bg-accent-orange/10 text-accent-orange border border-accent-orange/30 rounded-md px-1.5 py-0.5">{cert.days_remaining}d remaining</span>
                    )}
                    {cert.self_signed && <span className="text-[10px] bg-accent-orange/10 text-accent-orange border border-accent-orange/30 rounded-md px-1.5 py-0.5">SELF-SIGNED</span>}
                    {!cert.expired && cert.days_remaining >= 30 && !cert.self_signed && (
                      <span className="text-[10px] bg-accent-green/10 text-accent-green border border-accent-green/30 rounded-md px-1.5 py-0.5">Valid · {cert.days_remaining}d</span>
                    )}
                  </div>
                </div>
              ))}
            </Section>
          )}
        </div>
      )}
    </div>
  )
}


function GeoIPTab() {
  const [ip, setIp] = useState('')
  const [result, setResult] = useState<GeoIPResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    if (!ip.trim()) return
    setLoading(true); setResult(null)
    try {
      const { data } = await toolboxApi.geoip(ip.trim())
      setResult(data)
    } catch { toast.error('GeoIP lookup failed') }
    finally { setLoading(false) }
  }

  const d = result?.data ?? {}

  return (
    <div className="space-y-4">
      <InputRow label="IP address" placeholder="1.2.3.4" value={ip} onChange={setIp} onSubmit={run} loading={loading} />
      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Section title="Location" icon={<MapPin className="w-4 h-4 text-accent-cyan" />}>
            <KV label="Country" value={d.country} />
            <KV label="Country code" value={d.countryCode} />
            <KV label="Region" value={d.regionName} />
            <KV label="City" value={d.city} />
            <KV label="ZIP" value={d.zip} />
            <KV label="Timezone" value={d.timezone} />
            {d.lat && d.lon && <KV label="Coordinates" value={`${d.lat}, ${d.lon}`} />}
          </Section>
          <Section title="Network" icon={<Globe className="w-4 h-4 text-accent-cyan" />}>
            <KV label="ISP" value={d.isp} />
            <KV label="Org" value={d.org} />
            <KV label="AS" value={d.as} />
            <KV label="AS name" value={d.asname} />
            <KV label="Reverse DNS" value={d.reverse} />
            {d.proxy && <KV label="Proxy / VPN" value="Yes" />}
            {d.hosting && <KV label="Hosting" value="Yes (datacenter)" />}
            {d.mobile && <KV label="Mobile" value="Yes" />}
          </Section>
        </div>
      )}
    </div>
  )
}


function CVETab() {
  const [cveId, setCveId] = useState('')
  const [result, setResult] = useState<CVELookupResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    const id = cveId.trim().toUpperCase()
    if (!id) return
    setLoading(true); setResult(null)
    try {
      const { data } = await toolboxApi.cveLookup(id)
      setResult(data)
    } catch { toast.error('CVE lookup failed') }
    finally { setLoading(false) }
  }

  // The backend proxies NVD's CVE 2.0 API as { cve_id, data: { vulnerabilities: [{ cve }] } },
  // or { cve_id, raw } if NVD's response couldn't be parsed as JSON.
  const cve = result?.data?.vulnerabilities?.[0]?.cve
  const description = cve?.descriptions?.find(d => d.lang === 'en')?.value ?? cve?.descriptions?.[0]?.value
  const cvssV3 = cve?.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve?.metrics?.cvssMetricV30?.[0]?.cvssData
  const cvssV2 = cve?.metrics?.cvssMetricV2?.[0]?.cvssData
  const references = cve?.references ?? []

  return (
    <div className="space-y-4">
      <InputRow label="CVE ID" placeholder="CVE-2024-1234" value={cveId} onChange={setCveId} onSubmit={run} loading={loading} />
      {result && !cve && (
        <Section title={result.cve_id ?? cveId} icon={<AlertTriangle className="w-4 h-4 text-accent-cyan" />}>
          {result.raw
            ? <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">{result.raw}</pre>
            : <p className="text-xs text-text-muted">No data found for this CVE.</p>
          }
        </Section>
      )}
      {cve && (
        <div className="space-y-4">
          <Section title={cve.id ?? cveId} icon={<AlertTriangle className="w-4 h-4 text-accent-cyan" />}>
            <KV label="Published" value={cve.published} />
            <KV label="Modified" value={cve.lastModified} />
            {cvssV3 && <KV label="CVSS v3" value={`${cvssV3.baseScore} (${cvssV3.baseSeverity ?? 'n/a'})`} />}
            {cvssV2 && <KV label="CVSS v2" value={String(cvssV2.baseScore ?? '')} />}
            {description && (
              <p className="text-xs text-text-secondary leading-relaxed mt-2">{description}</p>
            )}
          </Section>
          {references.length > 0 && (
            <Section title="References" icon={<Info className="w-4 h-4 text-accent-cyan" />}>
              {references.slice(0, 8).map((ref, i) => (
                <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer" className="block text-xs text-accent-cyan hover:underline truncate py-0.5">{ref.url}</a>
              ))}
            </Section>
          )}
        </div>
      )}
    </div>
  )
}


const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'whois', label: 'WHOIS',   icon: <Globe  className="w-3.5 h-3.5" /> },
  { id: 'ports', label: 'Ports',   icon: <Search className="w-3.5 h-3.5" /> },
  { id: 'cms',   label: 'CMS',     icon: <Terminal className="w-3.5 h-3.5" /> },
  { id: 'tls',   label: 'TLS',     icon: <Lock   className="w-3.5 h-3.5" /> },
  { id: 'geoip', label: 'GeoIP',   icon: <MapPin className="w-3.5 h-3.5" /> },
  { id: 'cve',   label: 'CVE',     icon: <AlertTriangle className="w-3.5 h-3.5" /> },
]

export default function ToolboxPage() {
  const [tab, setTab] = useState<Tab>('tls')

  return (
    <div className="p-6 space-y-4 max-w-4xl mx-auto">
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Toolbox</h1>
        <p className="text-sm text-text-muted">Standalone security utilities — no scan required.</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 bg-surface-1 rounded-lg border border-border w-fit">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all',
              tab === t.id
                ? 'bg-surface-3 text-text-primary shadow-sm'
                : 'text-text-muted hover:text-text-primary'
            )}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {tab === 'whois' && <WhoisTab />}
        {tab === 'ports' && <PortScanTab />}
        {tab === 'cms'   && <CMSTab />}
        {tab === 'tls'   && <TLSTab />}
        {tab === 'geoip' && <GeoIPTab />}
        {tab === 'cve'   && <CVETab />}
      </div>
    </div>
  )
}
