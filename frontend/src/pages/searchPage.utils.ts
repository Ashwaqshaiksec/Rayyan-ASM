export interface SearchResult { type: string; id: string; title: string; subtitle?: string }
export interface SearchResponse {
  domains: { id: string; name: string; status?: string }[]
  hosts: { id: string; ip: string; hostname?: string }[]
  subdomains: { id: string; fqdn: string }[]
  services: { id: string; port: number; service: string; host_ref?: string }[]
  technologies: { id: string; name: string; version?: string }[]
  findings: { id: string; title: string; severity: string }[]
  cloud_assets: { id: string; provider: string; account_id?: string; resource_id: string; name?: string }[]
  filters?: Record<string, string>
  types?: string[]
}

export function flatten(data: SearchResponse): SearchResult[] {
  // Defense in depth: the backend now always sends real arrays (see
  // internal/api/handlers/handlers.go), but a `?? []` here means any future
  // regression — or a similarly-shaped endpoint elsewhere — degrades to an
  // empty section instead of throwing `.map of null` and blanking the
  // whole page.
  return [
    ...(data.domains ?? []).map(d => ({ type: 'domain', id: d.id, title: d.name, subtitle: d.status })),
    ...(data.hosts ?? []).map(h => ({ type: 'host', id: h.id, title: h.ip, subtitle: h.hostname })),
    ...(data.subdomains ?? []).map(s => ({ type: 'subdomain', id: s.id, title: s.fqdn })),
    ...(data.services ?? []).map(s => ({ type: 'service', id: s.id, title: `${s.host_ref ?? ''}:${s.port}`, subtitle: s.service })),
    ...(data.technologies ?? []).map(t => ({ type: 'technology', id: t.id, title: t.name, subtitle: t.version })),
    ...(data.findings ?? []).map(f => ({ type: 'finding', id: f.id, title: f.title, subtitle: f.severity })),
    ...(data.cloud_assets ?? []).map(c => ({
      type: 'cloud_asset', id: c.id, title: c.name || c.resource_id, subtitle: `${c.provider}${c.account_id ? ' · ' + c.account_id : ''}`,
    })),
  ]
}
