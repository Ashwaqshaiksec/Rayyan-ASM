package intelligence

// export_test.go exposes the package-level base-URL vars as exported names
// so that package intelligence_test (engine_test.go) can swap them to point
// at httptest.Server instances. Only compiled during `go test`.

// Pointers to the vars — tests write through these to swap the base URL and
// restore it via defer.

// ShodanBaseURL is the test-accessible alias for shodanBaseURL.
var ShodanBaseURL = &shodanBaseURL

// CensysBaseURL is the test-accessible alias for censysBaseURL.
var CensysBaseURL = &censysBaseURL

// SecurityTrailsBaseURL is the test-accessible alias for securityTrailsBaseURL.
var SecurityTrailsBaseURL = &securityTrailsBaseURL

// HackerTargetBaseURL is the test-accessible alias for hackerTargetBaseURL.
var HackerTargetBaseURL = &hackerTargetBaseURL

// MonitorJob re-exports the type so engine_test.go can instantiate it
// without importing intelligence.MonitorJob directly — it's already in
// this package so no re-export is needed; this file just confirms the
// type is accessible from the _test package via the intelligence import.
