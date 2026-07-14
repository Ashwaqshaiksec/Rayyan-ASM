import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import Layout from '@/components/common/Layout'
import ErrorBoundary from '@/components/common/ErrorBoundary'

// ── Auth pages — loaded eagerly (always needed on first paint) ──────────────
import LoginPage from '@/pages/LoginPage'
import RegisterPage from '@/pages/RegisterPage'
import VerifyEmailPage from '@/pages/VerifyEmailPage'
import ResendVerificationPage from '@/pages/ResendVerificationPage'
import CheckEmailPage from '@/pages/CheckEmailPage'

// ── All other pages — lazy chunks, one per route ────────────────────────────
const DashboardPage          = lazy(() => import('@/pages/DashboardPage'))
const DomainsPage            = lazy(() => import('@/pages/DomainsPage'))
const DomainDetailPage       = lazy(() => import('@/pages/DomainDetailPage'))
const SubdomainsPage         = lazy(() => import('@/pages/SubdomainsPage'))
const HostsPage              = lazy(() => import('@/pages/HostsPage'))
const HostDetailPage         = lazy(() => import('@/pages/HostDetailPage'))
const ServicesPage           = lazy(() => import('@/pages/ServicesPage'))
const CertificatesPage       = lazy(() => import('@/pages/CertificatesPage'))
const DNSPage                = lazy(() => import('@/pages/DNSPage'))
const ScansPage              = lazy(() => import('@/pages/ScansPage'))
const ScanDetailPage         = lazy(() => import('@/pages/ScanDetailPage'))
const ScanComparePage        = lazy(() => import('@/pages/ScanComparePage'))
const AlertsPage             = lazy(() => import('@/pages/AlertsPage'))
const ReportsPage            = lazy(() => import('@/pages/ReportsPage'))
const CloudPage              = lazy(() => import('@/pages/CloudPage'))
const TakeoverPage           = lazy(() => import('@/pages/TakeoverPage'))
const TechnologiesPage       = lazy(() => import('@/pages/TechnologiesPage'))
const UsersPage              = lazy(() => import('@/pages/UsersPage'))
const AuditPage              = lazy(() => import('@/pages/AuditPage'))
const SettingsPage           = lazy(() => import('@/pages/SettingsPage'))
const SearchPage             = lazy(() => import('@/pages/SearchPage'))
const FindingsPage           = lazy(() => import('@/pages/FindingsPage'))
const ToolsPage              = lazy(() => import('@/pages/ToolsPage'))
const ToolRunHistoryPage     = lazy(() => import('@/pages/ToolRunHistoryPage'))
const ToolboxPage            = lazy(() => import('@/pages/ToolboxPage'))
const ScreenshotsPage        = lazy(() => import('@/pages/ScreenshotsPage'))
const SLAReportPage          = lazy(() => import('@/pages/SLAReportPage'))
const ASNPage                = lazy(() => import('@/pages/ASNPage'))
const RiskScorePage          = lazy(() => import('@/pages/RiskScorePage'))
const CorrelationPage        = lazy(() => import('@/pages/CorrelationPage'))
const AssetRelationshipsPage = lazy(() => import('@/pages/AssetRelationshipsPage'))
const ChangeTimelinePage     = lazy(() => import('@/pages/ChangeTimelinePage'))
const AttackPathPage         = lazy(() => import('@/pages/AttackPathPage'))
const ExecutiveDashboardPage = lazy(() => import('@/pages/ExecutiveDashboardPage'))
const ExposureCenterPage     = lazy(() => import('@/pages/ExposureCenterPage'))

const IntelligencePage       = lazy(() => import('@/pages/IntelligencePage'))
const WHOISHistoryPage       = lazy(() => import('@/pages/WHOISHistoryPage'))
const ProjectsPage           = lazy(() => import('@/pages/ProjectsPage'))

// Discovery sub-pages — each has its own stub file for consistent code-splitting.
const DiscoveryDashboardPage      = lazy(() => import('@/pages/DiscoveryDashboardPage'))
const DiscoveryJobsPage           = lazy(() => import('@/pages/DiscoveryJobsPage'))
const DiscoveryAssetInventoryPage = lazy(() => import('@/pages/DiscoveryAssetInventoryPage'))
const DiscoveryRiskFlagsPage      = lazy(() => import('@/pages/DiscoveryRiskFlagsPage'))
const NotFoundPage                = lazy(() => import('@/pages/NotFoundPage'))

// ── Route guards ─────────────────────────────────────────────────────────────
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  if (isAuthenticated) return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

// ── Fallback while lazy chunks load ─────────────────────────────────────────
function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

function Page({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageLoader />}>{children}</Suspense>
    </ErrorBoundary>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login"    element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
      <Route path="/verify-email"         element={<VerifyEmailPage />} />
      <Route path="/resend-verification"  element={<ResendVerificationPage />} />
      <Route path="/check-email"          element={<CheckEmailPage />} />

      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/dashboard" replace />} />

        <Route path="dashboard" element={<Page><DashboardPage /></Page>} />
        <Route path="executive" element={<Page><ExecutiveDashboardPage /></Page>} />

        <Route path="domains"           element={<Page><DomainsPage /></Page>} />
        <Route path="domains/:id"       element={<Page><DomainDetailPage /></Page>} />
        <Route path="subdomains"        element={<Page><SubdomainsPage /></Page>} />
        <Route path="hosts"             element={<Page><HostsPage /></Page>} />
        <Route path="hosts/:id"         element={<Page><HostDetailPage /></Page>} />
        <Route path="services"          element={<Page><ServicesPage /></Page>} />
        <Route path="certificates"      element={<Page><CertificatesPage /></Page>} />
        <Route path="dns"               element={<Page><DNSPage /></Page>} />
        <Route path="technologies"      element={<Page><TechnologiesPage /></Page>} />
        <Route path="asn"               element={<Page><ASNPage /></Page>} />
        <Route path="asn-ranges"        element={<Page><ASNPage /></Page>} />
        <Route path="screenshots"       element={<Page><ScreenshotsPage /></Page>} />

        <Route path="scans"             element={<Page><ScansPage /></Page>} />
        <Route path="scans/:id/compare" element={<Page><ScanComparePage /></Page>} />
        <Route path="scans/:id"         element={<Page><ScanDetailPage /></Page>} />

        <Route path="findings"          element={<Page><FindingsPage /></Page>} />
        <Route path="findings/sla-report" element={<Page><SLAReportPage /></Page>} />
        <Route path="exposure"          element={<Page><ExposureCenterPage /></Page>} />
        <Route path="risk"              element={<Page><RiskScorePage /></Page>} />
        <Route path="correlation"       element={<Page><CorrelationPage /></Page>} />
        <Route path="relationships"     element={<Page><AssetRelationshipsPage /></Page>} />
        <Route path="changes"           element={<Page><ChangeTimelinePage /></Page>} />
        <Route path="attack-paths"      element={<Page><AttackPathPage /></Page>} />

        <Route path="alerts"            element={<Page><AlertsPage /></Page>} />
        <Route path="reports"           element={<Page><ReportsPage /></Page>} />
        <Route path="cloud"             element={<Page><CloudPage /></Page>} />
        <Route path="takeover"          element={<Page><TakeoverPage /></Page>} />

        <Route path="tools"             element={<Page><ToolsPage /></Page>} />
        <Route path="tools/:name/history" element={<Page><ToolRunHistoryPage /></Page>} />
        <Route path="toolbox"           element={<Page><ToolboxPage /></Page>} />

        <Route path="intelligence"       element={<Page><IntelligencePage /></Page>} />
        <Route path="whois-history"        element={<Page><WHOISHistoryPage /></Page>} />
        <Route path="projects"             element={<Page><ProjectsPage /></Page>} />
        <Route path="discovery"         element={<Page><DiscoveryDashboardPage /></Page>} />
        <Route path="discovery/jobs"    element={<Page><DiscoveryJobsPage /></Page>} />
        <Route path="discovery/assets"  element={<Page><DiscoveryAssetInventoryPage /></Page>} />
        <Route path="discovery/risks"   element={<Page><DiscoveryRiskFlagsPage /></Page>} />

        <Route path="search"            element={<Page><SearchPage /></Page>} />
        <Route path="users"             element={<Page><UsersPage /></Page>} />
        <Route path="audit"             element={<Page><AuditPage /></Page>} />
        <Route path="settings"          element={<Page><SettingsPage /></Page>} />

        {/* Unmatched paths inside the app shell get a real 404 with the
            sidebar/topbar still present, instead of silently bouncing to
            the dashboard with no explanation. */}
        <Route path="*" element={<Page><NotFoundPage /></Page>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
