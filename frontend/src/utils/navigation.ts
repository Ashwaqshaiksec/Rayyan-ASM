import {
  LayoutDashboard, Globe, Network, Server, Shield,
  FileCode2, Scan, Bell, FileText, Cloud, Cpu,
  Users, ClipboardList, Settings,
  Radar, Bug, Wrench, FlaskConical,
  Camera, Layers, Gauge, Share2, History, Swords, Briefcase, GitBranch, Crosshair,
  Telescope, Database, Brain, FolderOpen, Search,
} from 'lucide-react'

export type NavItem = { label: string; path: string; icon: typeof LayoutDashboard; role?: string }

export const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: 'Overview',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
      { label: 'Executive', path: '/executive', icon: Briefcase },
    ],
  },
  {
    label: 'Discovery & Intel',
    items: [
      { label: 'External Discovery', path: '/discovery', icon: Telescope },
      { label: 'Intelligence', path: '/intelligence', icon: Brain },
      { label: 'WHOIS History', path: '/whois-history', icon: Database },
    ],
  },
  {
    label: 'Risk & Analysis',
    items: [
      { label: 'Risk Scoring', path: '/risk', icon: Gauge },
      { label: 'Correlation', path: '/correlation', icon: Share2 },
      { label: 'Relationships', path: '/relationships', icon: GitBranch },
      { label: 'Changes', path: '/changes', icon: History },
      { label: 'Attack Paths', path: '/attack-paths', icon: Swords },
      { label: 'Exposure Center', path: '/exposure', icon: Crosshair },
    ],
  },
  {
    label: 'Assets',
    items: [
      { label: 'Domains', path: '/domains', icon: Globe },
      { label: 'Subdomains', path: '/subdomains', icon: Network },
      { label: 'Hosts / IPs', path: '/hosts', icon: Server },
      { label: 'Services', path: '/services', icon: Cpu },
      { label: 'Certificates', path: '/certificates', icon: Shield },
      { label: 'DNS Records', path: '/dns', icon: FileCode2 },
      { label: 'Cloud Assets', path: '/cloud', icon: Cloud },
      { label: 'Takeover', path: '/takeover', icon: Crosshair },
      { label: 'Technologies', path: '/technologies', icon: Radar },
      { label: 'Screenshots', path: '/screenshots', icon: Camera },
      { label: 'ASN Ranges', path: '/asn-ranges', icon: Layers },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Scans', path: '/scans', icon: Scan },
      { label: 'Alerts', path: '/alerts', icon: Bell },
      { label: 'Findings', path: '/findings', icon: Bug },
      { label: 'Reports', path: '/reports', icon: FileText },
      { label: 'Tools', path: '/tools', icon: Wrench },
      { label: 'Toolbox', path: '/toolbox', icon: FlaskConical },
      { label: 'Projects', path: '/projects', icon: FolderOpen },
      { label: 'Search', path: '/search', icon: Search },
    ],
  },
  {
    label: 'Admin',
    items: [
      { label: 'Users', path: '/users', icon: Users, role: 'admin' },
      { label: 'Audit Log', path: '/audit', icon: ClipboardList, role: 'admin' },
      { label: 'Settings', path: '/settings', icon: Settings },
    ],
  },
]

export const allNavItems = navGroups.flatMap((g) => g.items)
