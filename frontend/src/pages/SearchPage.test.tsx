import { describe, it, expect } from 'vitest'
import { flatten } from './searchPage.utils'

describe('SearchPage result flattening', () => {
  it('flattens every entity group the backend actually returns', () => {
    // The backend /search response has no top-level "results" field — it
    // returns domains/hosts/subdomains/services/technologies/findings/
    // cloud_assets as separate arrays. The previous implementation read
    // data.results (undefined) and silently showed "No results found" for
    // every query.
    const data = {
      domains: [{ id: 'd1', name: 'example.com', status: 'active' }],
      hosts: [{ id: 'h1', ip: '1.2.3.4', hostname: 'web1' }],
      subdomains: [{ id: 's1', fqdn: 'api.example.com' }],
      services: [{ id: 'sv1', port: 443, service: 'https', host_ref: '1.2.3.4' }],
      technologies: [{ id: 't1', name: 'nginx', version: '1.25' }],
      findings: [{ id: 'f1', title: 'Exposed admin panel', severity: 'critical' }],
      cloud_assets: [{ id: 'c1', provider: 'aws', account_id: '111111111111', resource_id: 'i-abc123', name: 'web-1' }],
    }

    const result = flatten(data)

    expect(result).toHaveLength(7)
    expect(result.find(r => r.type === 'domain')?.title).toBe('example.com')
    expect(result.find(r => r.type === 'host')?.title).toBe('1.2.3.4')
    expect(result.find(r => r.type === 'subdomain')?.title).toBe('api.example.com')
    expect(result.find(r => r.type === 'service')?.title).toBe('1.2.3.4:443')
    expect(result.find(r => r.type === 'technology')?.title).toBe('nginx')
    expect(result.find(r => r.type === 'finding')?.title).toBe('Exposed admin panel')
    const cloudResult = result.find(r => r.type === 'cloud_asset')
    expect(cloudResult?.title).toBe('web-1')
    expect(cloudResult?.subtitle).toBe('aws · 111111111111')
  })

  it('falls back to resource_id when a cloud asset has no name', () => {
    const data = {
      domains: [], hosts: [], subdomains: [], services: [], technologies: [], findings: [],
      cloud_assets: [{ id: 'c2', provider: 'gcp', resource_id: 'instance-42' }],
    }
    const result = flatten(data)
    expect(result).toHaveLength(1)
    expect(result[0].title).toBe('instance-42')
    expect(result[0].subtitle).toBe('gcp')
  })

  it('returns an empty array when every group is empty', () => {
    const empty = { domains: [], hosts: [], subdomains: [], services: [], technologies: [], findings: [], cloud_assets: [] }
    expect(flatten(empty)).toEqual([])
  })

  it('does not throw if the backend sends null instead of [] for an empty category', () => {
    // Regression guard: a Go `var x []T` that's never populated marshals as
    // JSON null, not []. The backend has been fixed to always send real
    // arrays, but flatten() should degrade gracefully rather than throw
    // `.map of null` if that ever regresses (here or on a similar endpoint).
    const withNulls = {
      domains: [{ id: 'd1', name: 'example.com' }],
      hosts: null, subdomains: null, services: null, technologies: null, findings: null, cloud_assets: null,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any
    expect(() => flatten(withNulls)).not.toThrow()
    expect(flatten(withNulls)).toEqual([{ type: 'domain', id: 'd1', title: 'example.com', subtitle: undefined }])
  })
})
