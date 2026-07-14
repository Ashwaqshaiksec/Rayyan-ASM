import {
  LayoutDashboard, Globe, Network, Server, Shield,
  FileCode2, Scan, Bell, FileText, Cloud, Cpu,
  Users, ClipboardList, Settings,
  Radar, Bug, Wrench, FlaskConical,
  Camera, Layers, Gauge, Share2, History, Swords, Briefcase, GitBranch, Crosshair,
  Telescope, Database, Brain, FolderOpen, Search, type LucideIcon,
} from 'lucide-react'

export interface HelpModule {
  /** Route path as it appears in the URL, e.g. '/dashboard'. */
  path: string
  /** Nav group this page belongs to — mirrors utils/navigation.ts. */
  group: string
  label: string
  icon: LucideIcon
  /** One-line description shown in list/search views. */
  summary: string
  /** 2-4 sentence explanation of what the page is and why it exists. */
  overview: string
  /** Concrete, ordered steps for using the page. */
  howTo: string[]
  /** Optional call-outs: gotchas, shortcuts, related pages. */
  tips?: string[]
  /** Other exact route paths that should resolve to this same module (legacy/alias routes). */
  aliases?: string[]
}

export const helpModules: HelpModule[] = [
  // ─── Overview ────────────────────────────────────────────────────────────
  {
    path: '/dashboard',
    group: 'Overview',
    label: 'Dashboard',
    icon: LayoutDashboard,
    summary: 'At-a-glance health of your attack surface.',
    overview: 'The Dashboard is your landing page — a rollup of asset counts, open findings by severity, recent scan activity, and any alerts that need attention. It\'s meant for a five-second "is anything on fire" check, not deep analysis.',
    howTo: [
      'Scan the summary cards for asset totals and open-finding counts by severity.',
      'Use the recent activity feed to see the latest scans and discovered changes.',
      'Click through any card or chart to jump to the full page behind it (Findings, Scans, etc).',
    ],
    tips: ['For a leadership-oriented view with business-impact framing, use Executive instead.'],
  },
  {
    path: '/executive',
    group: 'Overview',
    label: 'Executive',
    icon: Briefcase,
    summary: 'Organization-wide exposure, risk, and business impact overview.',
    overview: 'Executive Dashboard reframes the same underlying data as Dashboard for a non-technical audience — trends over time, risk posture, and impact framing rather than raw counts. Built for status updates and reporting upward.',
    howTo: [
      'Review the headline risk/exposure trend to see if posture is improving or degrading.',
      'Use the breakdowns to identify which asset categories or business units are driving risk.',
      'Export or screenshot the view for status decks — it\'s intentionally presentation-ready.',
    ],
  },

  // ─── Discovery & Intel ───────────────────────────────────────────────────
  {
    path: '/discovery',
    group: 'Discovery & Intel',
    label: 'External Discovery',
    icon: Telescope,
    summary: 'Continuously map every internet-facing asset from a handful of seed domains.',
    overview: 'External Discovery runs the automated mapping pipeline: starting from seed domains, it enumerates subdomains, resolves IPs, fingerprints services, and pulls certificates on a recurring schedule — building the asset inventory that the rest of Rayyan works from.',
    howTo: [
      'Confirm your seed domains are configured (add them from the Domains page if not).',
      'Check the dashboard tab for pipeline status and last-run summary.',
      'Drill into Discovery Jobs for run history, or Discovered Asset Inventory for what\'s been found.',
      'Review Discovery Risk Flags for anything surfaced that needs immediate triage.',
    ],
    tips: ['This is passive/automated mapping — for an on-demand, single-target lookup use Toolbox instead.'],
  },
  {
    path: '/discovery/jobs',
    group: 'Discovery & Intel',
    label: 'Discovery Jobs',
    icon: Telescope,
    summary: 'History of every discovery pipeline run, including recurring scheduled runs.',
    overview: 'A log of past and in-progress discovery runs, so you can confirm the pipeline is actually executing on schedule and see how long each run took.',
    howTo: [
      'Check status and duration of the most recent run.',
      'Click into a job for the assets or errors it produced, if available.',
    ],
  },
  {
    path: '/discovery/assets',
    group: 'Discovery & Intel',
    label: 'Discovered Asset Inventory',
    icon: Telescope,
    summary: 'Every internet-facing asset surfaced by the External Discovery Engine.',
    overview: 'A consolidated inventory view — domains, subdomains, IPs, certificates, and services — grouped by type, as discovered rather than as manually tracked. Useful for confirming discovery is actually finding what you expect.',
    howTo: [
      'Expand each asset-type section (Domains, Subdomains, IP Addresses, Certificates, Services) to review what was found.',
      'Cross-check against the dedicated Assets pages (Domains, Hosts, etc.) if something looks missing.',
    ],
  },
  {
    path: '/discovery/risks',
    group: 'Discovery & Intel',
    label: 'Discovery Risk Flags',
    icon: Telescope,
    summary: 'Exposed admin panels, VPN portals, login pages, expired certs, and shadow IT.',
    overview: 'A triage list of notable-but-not-yet-a-finding items the discovery engine flags as it maps your surface — the kind of thing worth a human glance even before a full scan runs.',
    howTo: [
      'Review flagged items, prioritizing exposed admin/VPN/login surfaces and expired certificates.',
      'Investigate anything unexpected — it may indicate shadow IT or an unmanaged asset.',
    ],
  },
  {
    path: '/intelligence',
    group: 'Discovery & Intel',
    label: 'Intelligence',
    icon: Brain,
    summary: 'Threat intel enrichment — breach exposure, leaked credentials, dark-web mentions, and related signal.',
    overview: 'Intelligence pulls in external threat-intel sources to enrich your known assets and identities with context that scanning alone won\'t find — breach data, exposed credentials, and related signals tied back to your domains.',
    howTo: [
      'Select a domain or identity to enrich, or review existing enrichment results.',
      'Read through returned signal and cross-reference against active Findings where relevant.',
    ],
    tips: ['Some intelligence sources are rate-limited or subscription-gated — check Settings → Integrations if a source returns nothing.'],
  },
  {
    path: '/whois-history',
    group: 'Discovery & Intel',
    label: 'WHOIS History',
    icon: Database,
    summary: 'Track WHOIS record changes over time for any domain.',
    overview: 'Keeps a historical record of WHOIS lookups per domain, so registrar, nameserver, or ownership changes are visible over time rather than only as a single current snapshot.',
    howTo: [
      'Pick a domain to view its WHOIS history timeline.',
      'Compare entries to spot registrar transfers, nameserver changes, or expiry-date drift.',
    ],
    tips: ['For a one-off current-state WHOIS lookup on any domain, Toolbox is faster.'],
  },

  // ─── Risk & Analysis ─────────────────────────────────────────────────────
  {
    path: '/risk',
    group: 'Risk & Analysis',
    label: 'Risk Scoring',
    icon: Gauge,
    summary: 'Asset risk across hosts, subdomains, and domains.',
    overview: 'Computes and displays a risk score per asset, rolled up from factors like open findings, exposed services, and certificate health, with trend overlays so you can see whether risk is climbing or falling over time.',
    howTo: [
      'Sort or filter assets by score to find your highest-risk items first.',
      'Open the trend view on an asset to see how its score has moved and what changed.',
    ],
  },
  {
    path: '/correlation',
    group: 'Risk & Analysis',
    label: 'Correlation',
    icon: Share2,
    summary: 'Relationship graph across domains, hosts, services, and shared infrastructure.',
    overview: 'Visualizes how assets connect — shared IPs, shared certificates, shared nameservers — to surface infrastructure relationships that aren\'t obvious from flat asset lists.',
    howTo: [
      'Select an asset as the graph focus.',
      'Follow edges to shared infrastructure that might expand your understanding of blast radius.',
    ],
  },
  {
    path: '/relationships',
    group: 'Risk & Analysis',
    label: 'Relationships',
    icon: GitBranch,
    summary: 'Connectivity, blast-radius hubs, and unmapped assets across the relationship graph.',
    overview: 'A more analytical companion to Correlation, calling out hub assets (high connectivity, so a compromise would cascade widely) and assets that sit outside the mapped graph entirely.',
    howTo: [
      'Check the hub list for assets whose compromise would have outsized blast radius.',
      'Review unmapped assets — they may need manual linking or represent gaps in discovery.',
    ],
  },
  {
    path: '/changes',
    group: 'Risk & Analysis',
    label: 'Changes',
    icon: History,
    summary: 'New, removed, and changed assets across domains, hosts, services, certs, DNS, and technologies.',
    overview: 'The "what changed" feed — a chronological timeline of asset additions, removals, and modifications detected across scan and discovery runs, so drift is visible without diffing snapshots yourself.',
    howTo: [
      'Scroll the timeline for recent changes, filtering by asset type if you\'re looking for something specific.',
      'Use it after a scan completes to quickly see what\'s new versus the prior baseline.',
    ],
  },
  {
    path: '/attack-paths',
    group: 'Risk & Analysis',
    label: 'Attack Paths',
    icon: Swords,
    summary: 'Ranked exposure chains from internet-facing assets to sensitive targets.',
    overview: 'Models plausible attack chains — kill-chain style — from your externally exposed assets toward sensitive targets, ranked by weakest-link risk, using the AttackPathFlow diagram to visualize each hop.',
    howTo: [
      'Open the ranked list and start with the top (highest-risk) path.',
      'Step through the diagram to see each hop and the specific weakness that enables it.',
    ],
  },
  {
    path: '/exposure',
    group: 'Risk & Analysis',
    label: 'Exposure Center',
    icon: Crosshair,
    summary: 'Real-world attackability and business impact — blended across risk, exposure, attack paths, and the asset graph.',
    overview: 'The most synthesized risk view in Rayyan: rather than any single signal (CVSS, risk score, etc.), it blends exposure, attack-path reachability, and business impact into one prioritized picture of what\'s actually attackable.',
    howTo: [
      'Start here when deciding what to fix first — it\'s designed to outrank raw CVSS sorting.',
      'Drill into a top item to see which underlying signals (risk, exposure, path) are driving its ranking.',
    ],
  },

  // ─── Assets ──────────────────────────────────────────────────────────────
  {
    path: '/domains',
    group: 'Assets',
    label: 'Domains',
    icon: Globe,
    summary: 'Your seed domains — the starting point for discovery and monitoring.',
    overview: 'Domains you own or manage, added here as seeds. Everything else (subdomain enumeration, DNS resolution, certificate tracking) builds outward from this list.',
    howTo: [
      'Add a domain to start tracking it.',
      'Open a domain\'s detail page for its subdomains, DNS records, certs, and history in one place.',
    ],
    tips: ['Adding a domain here is the prerequisite for External Discovery to pick it up as a seed.'],
  },
  {
    path: '/subdomains',
    group: 'Assets',
    label: 'Subdomains',
    icon: Network,
    summary: 'All subdomains enumerated across your tracked domains.',
    overview: 'A flat, filterable list of every subdomain discovery has found, independent of which parent domain page you\'re on.',
    howTo: [
      'Filter or search to find a specific subdomain.',
      'Click through to see resolved IPs and related services.',
    ],
  },
  {
    path: '/hosts',
    group: 'Assets',
    label: 'Hosts / IPs',
    icon: Server,
    summary: 'Discovered hosts and IP addresses, with ASN and geo enrichment.',
    overview: 'Every resolved host/IP in your attack surface, enriched with ASN and geolocation data where available. This is the asset-level view that services, certs, and findings ultimately hang off of.',
    howTo: [
      'Filter by ASN, geo, or hostname to narrow the list.',
      'Open a host\'s detail page for its full service and finding history.',
    ],
  },
  {
    path: '/services',
    group: 'Assets',
    label: 'Services',
    icon: Cpu,
    summary: 'Open ports and running services detected on your hosts.',
    overview: 'A service-level view of what\'s actually listening on your hosts — port, protocol, and banner/fingerprint data from scans.',
    howTo: [
      'Filter by port or service name to find specific exposure.',
      'Cross-reference with Findings to see if a service has an associated vulnerability.',
    ],
  },
  {
    path: '/certificates',
    group: 'Assets',
    label: 'Certificates',
    icon: Shield,
    summary: 'TLS certificates across your domains, with expiry tracking.',
    overview: 'Every certificate discovery has found, with an expiring-soon callout so you don\'t get caught by a lapsed cert on a production endpoint.',
    howTo: [
      'Check the expiring-in-30-days count in the header first.',
      'Open a cert for its chain, issuer, and which domains/hosts present it.',
    ],
  },
  {
    path: '/dns',
    group: 'Assets',
    label: 'DNS Records',
    icon: FileCode2,
    summary: 'DNS records resolved across your tracked domains.',
    overview: 'A record-level view (A, AAAA, MX, TXT, etc.) of DNS as currently resolved, useful for spotting stale records, unexpected third-party pointers, or SPF/DMARC gaps.',
    howTo: [
      'Filter by record type or domain.',
      'Cross-check TXT records for SPF/DKIM/DMARC configuration issues.',
    ],
  },
  {
    path: '/cloud',
    group: 'Assets',
    label: 'Cloud Assets',
    icon: Cloud,
    summary: 'Cloud resources (AWS, Azure, GCP, etc.) tied to your organization.',
    overview: 'Cloud-provider assets — storage buckets, compute instances, and similar — discovered or manually tracked, grouped by provider and account.',
    howTo: [
      'Filter by provider or account to scope the view.',
      'Watch for publicly-exposed storage or compute — a common source of unintentional exposure.',
    ],
  },
  {
    path: '/takeover',
    group: 'Assets',
    label: 'Takeover',
    icon: Crosshair,
    summary: 'Subdomains vulnerable to takeover via dangling DNS records.',
    overview: 'Flags subdomains pointing at third-party services (CDNs, PaaS, SaaS) that are no longer provisioned on the other end — the classic subdomain-takeover exposure.',
    howTo: [
      'Review flagged subdomains and confirm whether the referenced third-party resource still exists.',
      'Remediate by removing the dangling DNS record or reclaiming the resource.',
    ],
  },
  {
    path: '/technologies',
    group: 'Assets',
    label: 'Technologies',
    icon: Radar,
    summary: 'Web technologies and software fingerprinted across your assets.',
    overview: 'Technology fingerprints (frameworks, CMS, server software, JS libraries) detected during scans, so you can see your software footprint and cross-reference against known CVEs.',
    howTo: [
      'Filter by technology name to see everywhere it\'s deployed.',
      'Use this to scope impact when a new CVE drops for a specific piece of software.',
    ],
  },
  {
    path: '/screenshots',
    group: 'Assets',
    label: 'Screenshots',
    icon: Camera,
    summary: 'Captured screenshots of web assets.',
    overview: 'Visual snapshots of web-facing assets taken during scans — useful for quickly eyeballing what\'s actually running on an endpoint without visiting it directly.',
    howTo: [
      'Browse the gallery to visually triage unfamiliar assets.',
      'Use alongside Technologies/Findings to confirm what a flagged endpoint actually looks like.',
    ],
  },
  {
    path: '/asn-ranges',
    aliases: ['/asn'],
    group: 'Assets',
    label: 'ASN Ranges',
    icon: Layers,
    summary: 'Enumerate CIDRs belonging to an ASN.',
    overview: 'Looks up the IP ranges (CIDRs) announced by a given Autonomous System Number, useful for scoping discovery around infrastructure you know is yours by ASN rather than by domain.',
    howTo: [
      'Enter an ASN to list its announced CIDR ranges.',
      'Cross-reference returned ranges against Hosts to see what\'s already been discovered within them.',
    ],
  },

  // ─── Operations ──────────────────────────────────────────────────────────
  {
    path: '/scans',
    group: 'Operations',
    label: 'Scans',
    icon: Scan,
    summary: 'All scan jobs — the tool pipeline run against your assets.',
    overview: 'Scans run the actual tool pipeline (subdomain enum, port scanning, vuln checks, and more) against your assets and are the primary source of Findings. This page lists every job, running or completed.',
    howTo: [
      'Start a new scan by picking targets and a tool profile.',
      'Track progress from here; open a completed scan for its full result set.',
      'Use Compare on two scans to see what changed between runs.',
    ],
    tips: ['For a single, fast, no-job-required lookup, use Toolbox instead of kicking off a full scan.'],
  },
  {
    path: '/scans/:id/compare',
    group: 'Operations',
    label: 'Scan Compare',
    icon: Scan,
    summary: 'Diff two scans — new findings, removed/fixed findings, and persistent ones.',
    overview: 'Side-by-side comparison of two scan runs, bucketed into new findings, removed/fixed findings, and ones that persisted across both — the fastest way to see what a scan actually changed.',
    howTo: [
      'Open from a scan\'s detail page via the Compare action.',
      'Review the three buckets to focus attention on genuinely new issues.',
    ],
  },
  {
    path: '/alerts',
    group: 'Operations',
    label: 'Alerts',
    icon: Bell,
    summary: 'Notifications for events that need attention.',
    overview: 'A feed of system-generated alerts — new critical findings, certificate expiry, discovery anomalies — that you can acknowledge or resolve to keep the queue actionable.',
    howTo: [
      'Acknowledge an alert once you\'ve seen it, resolve it once it\'s handled.',
      'Configure which events generate alerts and where they\'re delivered from Settings → Notifications.',
    ],
  },
  {
    path: '/findings',
    group: 'Operations',
    label: 'Findings',
    icon: Bug,
    summary: 'Every vulnerability or issue a scan has turned up.',
    overview: 'The core triage queue: findings from scans, with severity, CVE/CVSS data where available, and a status you move through acknowledged → fixed (or mark as a false positive).',
    howTo: [
      'Sort by severity to prioritize triage.',
      'Update status as you work through the queue (acknowledge, mark fixed, or flag false positive).',
      'Use the SLA Report to check aging findings against remediation deadlines.',
    ],
  },
  {
    path: '/findings/sla-report',
    group: 'Operations',
    label: 'SLA Report',
    icon: FileText,
    summary: 'Findings tracked against remediation SLA deadlines.',
    overview: 'Shows open findings against your configured SLA windows by severity, surfacing what\'s at risk of breaching or has already breached its remediation deadline.',
    howTo: [
      'Check the breached/at-risk sections first.',
      'Configure SLA windows per severity from Settings if they need adjusting.',
    ],
  },
  {
    path: '/reports',
    group: 'Operations',
    label: 'Reports',
    icon: FileText,
    summary: 'Generate and export executive or technical reports.',
    overview: 'Turns current asset, risk, and finding data into a shareable report — for stakeholders who need a document rather than a live dashboard.',
    howTo: [
      'Pick a report type and scope (org-wide, a project, or a specific asset set).',
      'Generate and export/download the result.',
    ],
  },
  {
    path: '/tools',
    group: 'Operations',
    label: 'Tools',
    icon: Wrench,
    summary: 'Manage the 60+ scan tools Rayyan integrates with.',
    overview: 'Configuration and status for every integrated scan tool — installation checks, rate limits, and credentials required for tools that need API keys.',
    howTo: [
      'Check a tool\'s install status; use re-check if it\'s showing as unavailable.',
      'Adjust rate limits or credentials as needed.',
      'View a tool\'s run history to see recent invocations and their outcomes.',
    ],
  },
  {
    path: '/tools/:name/history',
    group: 'Operations',
    label: 'Tool Run History',
    icon: Wrench,
    summary: 'Recent invocations of a specific tool and their outcomes.',
    overview: 'Per-tool execution log, useful for debugging a tool that\'s failing silently or confirming it\'s actually being invoked during scans.',
    howTo: ['Open from a tool\'s row on the Tools page via "view run history".'],
  },
  {
    path: '/toolbox',
    group: 'Operations',
    label: 'Toolbox',
    icon: FlaskConical,
    summary: 'On-demand, single-target lookups — no scan job required.',
    overview: 'Fast one-off checks against a single target: WHOIS/RDAP, WHOIS history, CMS detection, TLS/certificate inspection, GeoIP, and CVE lookup — for when you need an instant answer without starting a full scan.',
    howTo: [
      'Pick the check you need (WHOIS, CMS, TLS, GeoIP, CVE) and enter a target.',
      'Read the result inline — each check renders its own detail sections.',
    ],
    tips: ['This is the quickest path when you just need to check one thing right now, as opposed to Scans which runs the full pipeline.'],
  },
  {
    path: '/projects',
    group: 'Operations',
    label: 'Projects',
    icon: FolderOpen,
    summary: 'Group assets, scans, and notes under named projects.',
    overview: 'Projects let you scope work — client engagements, business units, environments — so assets and activity can be organized and reported on independently rather than as one flat organization-wide pool.',
    howTo: [
      'Create a project and assign assets or scans to it.',
      'Use the notes panel to track engagement-specific context.',
    ],
    tips: ['Project slugs must be unique within your org.'],
  },
  {
    path: '/search',
    group: 'Operations',
    label: 'Search',
    icon: Search,
    summary: 'Field-qualified query search across every asset type at once.',
    overview: 'A unified search across domains, hosts, subdomains, services, technologies, findings, and cloud assets, using a query syntax that combines field filters with free text rather than a single flat keyword box.',
    howTo: [
      'Type a plain keyword for a free-text search across all types, or use field-qualified syntax (e.g. type:finding severity:high) to narrow results.',
      'Save a search you\'ll want to reuse — it\'ll persist for quick access later.',
      'Results are grouped by asset type; click through to the underlying record.',
    ],
    tips: ['Use the Command Palette (Ctrl/Cmd+K) for quick navigation — Search is for combing through data, not jumping between pages.'],
  },

  // ─── Admin ───────────────────────────────────────────────────────────────
  {
    path: '/users',
    group: 'Admin',
    label: 'Users',
    icon: Users,
    summary: 'Manage organization members and their roles.',
    overview: 'Admin-only member management — invite users, adjust roles, and remove access.',
    howTo: [
      'Invite a new member by email and assign a role.',
      'Adjust or revoke a member\'s role/access as needed.',
    ],
  },
  {
    path: '/audit',
    group: 'Admin',
    label: 'Audit Log',
    icon: ClipboardList,
    summary: 'Record of all privileged actions taken in the org.',
    overview: 'An admin-only audit trail of privileged actions — user changes, credential edits, settings changes — for accountability and incident review.',
    howTo: [
      'Filter by user, action type, or date range to investigate a specific event.',
    ],
  },
  {
    path: '/settings',
    group: 'Admin',
    label: 'Settings',
    icon: Settings,
    summary: 'Org configuration: profile, notifications, integrations, API credentials, and theme.',
    overview: 'Central configuration hub — account/org profile, notification channels, integration API keys, personal API tokens, and interface theme all live here.',
    howTo: [
      'Use the tabbed sections to find the setting you need (profile, notifications, integrations, tokens, appearance).',
      'Configure notification channels here if you want alerts delivered outside the app (e.g. email, webhook).',
      'Generate or revoke personal API tokens for scripted access.',
    ],
  },
]

/**
 * Resolve the most specific help module for a given pathname, matching
 * dynamic segments (e.g. '/domains/123' -> '/domains') when there's no
 * exact match for a detail-page route.
 */
export function findHelpModule(pathname: string): HelpModule | undefined {
  const exact = helpModules.find((m) => m.path === pathname)
  if (exact) return exact

  const aliased = helpModules.find((m) => m.aliases?.includes(pathname))
  if (aliased) return aliased

  // Try dynamic-route templates like '/scans/:id/compare' or '/tools/:name/history'.
  const segments = pathname.split('/').filter(Boolean)
  const templated = helpModules.find((m) => {
    const templateSegments = m.path.split('/').filter(Boolean)
    if (templateSegments.length !== segments.length) return false
    return templateSegments.every((seg, i) => seg.startsWith(':') || seg === segments[i])
  })
  if (templated) return templated

  // Fall back to a prefix match against the longest registered path
  // (e.g. '/domains/123' -> '/domains', '/scans/123' -> '/scans').
  const byPrefix = helpModules
    .filter((m) => !m.path.includes(':') && pathname.startsWith(m.path) && pathname !== m.path)
    .sort((a, b) => b.path.length - a.path.length)[0]
  return byPrefix
}

export const helpGroups: string[] = Array.from(new Set(helpModules.map((m) => m.group)))
