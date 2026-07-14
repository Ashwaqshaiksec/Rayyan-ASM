package toolrunner

import "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"

// RegisterAll populates the DefaultRegistry with all known tools.
func RegisterAll() {
	for _, t := range []ToolInfo{
		{Name: "subfinder", Category: CategorySubdomain, Description: "Passive subdomain enumeration", VersionFlag: "-version", Enabled: true},
		{Name: "amass", Category: CategorySubdomain, Description: "In-depth subdomain enumeration", VersionFlag: "-version", Enabled: true, TimeoutSeconds: 3600},
		{Name: "assetfinder", Category: CategorySubdomain, Description: "Find domains and subdomains", VersionFlag: "--version", Enabled: true},
		{Name: "findomain", Category: CategorySubdomain, Description: "Subdomain finder", VersionFlag: "--version", Enabled: true},
		{Name: "theHarvester", Category: CategorySubdomain, Description: "OSINT email/subdomain harvester", VersionFlag: "--version", Enabled: true},
		{Name: "sublist3r", Category: CategorySubdomain, Description: "Fast subdomains enumeration tool", VersionFlag: "--version", Enabled: true},
		{Name: "subbrute", Category: CategorySubdomain, Description: "DNS brute-force subdomain scanner", VersionFlag: "--version", Enabled: true},
		{Name: "SubDomainizer", Category: CategorySubdomain, Description: "Find subdomains in JS files", VersionFlag: "--version", Enabled: false},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "dnsx", Category: CategoryDNS, Description: "Fast DNS toolkit", VersionFlag: "-version", Enabled: true},
		{Name: "dnsrecon", Category: CategoryDNS, Description: "DNS enumeration tool", VersionFlag: "--version", Enabled: true},
		{Name: "dnsenum", Category: CategoryDNS, Description: "Multithreaded DNS enumeration", VersionFlag: "--version", Enabled: true},
		{Name: "dnstwist", Category: CategoryDNS, Description: "Domain name permutation engine", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "nmap", Category: CategoryNetwork, Description: "Network mapper", VersionFlag: "--version", Enabled: true},
		{Name: "naabu", Category: CategoryNetwork, Description: "Fast port scanner", VersionFlag: "-version", Enabled: true},
		{Name: "rustscan", Category: CategoryNetwork, Description: "Ultra-fast port scanner", VersionFlag: "--version", Enabled: true},
		{Name: "masscan", Category: CategoryNetwork, Description: "Mass IP port scanner", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "httpx", Category: CategoryWeb, Description: "HTTP probe toolkit", VersionFlag: "-version", Enabled: true},
		{Name: "katana", Category: CategoryWeb, Description: "Next-gen web crawler", VersionFlag: "-version", Enabled: true, TimeoutSeconds: 1800},
		{Name: "hakrawler", Category: CategoryWeb, Description: "Web crawler with JS parsing", VersionFlag: "--version", Enabled: true},
		{Name: "gau", Category: CategoryWeb, Description: "Get All URLs from open archives", VersionFlag: "--version", Enabled: true, MaxConcurrent: 2},
		{Name: "waybackurls", Category: CategoryWeb, Description: "Fetch Wayback Machine URLs", VersionFlag: "--version", Enabled: true, MaxConcurrent: 2},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "ffuf", Category: CategoryContent, Description: "Fast web fuzzer", VersionFlag: "-V", Enabled: true},
		{Name: "feroxbuster", Category: CategoryContent, Description: "Recursive content discovery", VersionFlag: "--version", Enabled: true, TimeoutSeconds: 1200},
		{Name: "gobuster", Category: CategoryContent, Description: "Directory/DNS/vhost brute-forcer", VersionFlag: "version", Enabled: true},
		{Name: "dirsearch", Category: CategoryContent, Description: "URL fuzzing tool", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "nuclei", Category: CategoryVulnerability, Description: "Template-based vulnerability scanner", VersionFlag: "-version", Enabled: true, TimeoutSeconds: 3600},
		{Name: "nikto", Category: CategoryVulnerability, Description: "Web server scanner", VersionFlag: "-Version", Enabled: true},
		{Name: "testssl.sh", Category: CategoryVulnerability, Description: "TLS/SSL testing", VersionFlag: "--version", Enabled: true, TimeoutSeconds: 1800},
	} {
		types.DefaultRegistry.Register(t)
	}

	types.DefaultRegistry.Register(ToolInfo{
		Name: "wafw00f", Category: CategoryWAF, Description: "WAF fingerprinting tool", VersionFlag: "--version", Enabled: true,
	})

	for _, t := range []ToolInfo{
		{Name: "smbclient", Category: CategorySMB, Description: "SMB share client", VersionFlag: "--version", Enabled: true, MaxConcurrent: 3},
		{Name: "enum4linux-ng", Category: CategorySMB, Description: "SMB/Samba enumeration", VersionFlag: "--version", Enabled: true, MaxConcurrent: 3},
		{Name: "crackmapexec", Category: CategorySMB, Description: "Network protocol attacks", VersionFlag: "--version", Enabled: false, MaxConcurrent: 1, MinIntervalSeconds: 5},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "cloudflair", Category: CategoryOriginIP, Description: "Find origin IPs behind CDN", VersionFlag: "--version", Enabled: true},
		{Name: "hakoriginfinder", Category: CategoryOriginIP, Description: "Find origin server for CDN hosts", VersionFlag: "--version", Enabled: true},
		{Name: "cloakquest3r", Category: CategoryOriginIP, Description: "Uncover real IPs behind Cloudflare", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "sqlmap", Category: CategoryInjection, Description: "SQL injection detection and exploitation", VersionFlag: "--version", Enabled: true, MaxConcurrent: 1, MinIntervalSeconds: 30},
		{Name: "dalfox", Category: CategoryInjection, Description: "XSS scanner (parameter analysis)", VersionFlag: "version", Enabled: true},
		{Name: "xsstrike", Category: CategoryInjection, Description: "XSS detection suite", VersionFlag: "--version", Enabled: true},
		{Name: "commix", Category: CategoryInjection, Description: "Automated command injection exploitation", VersionFlag: "--version", Enabled: true, MaxConcurrent: 1, MinIntervalSeconds: 10},
		{Name: "tplmap", Category: CategoryInjection, Description: "Server-Side Template Injection (SSTI) scanner", VersionFlag: "--version", Enabled: true},
		{Name: "crlfuzz", Category: CategoryInjection, Description: "CRLF injection scanner", VersionFlag: "-v", Enabled: true},
		{Name: "smuggler", Category: CategoryInjection, Description: "HTTP request smuggling detection (CL.TE/TE.CL)", VersionFlag: "--version", Enabled: true},
		{Name: "h2csmuggler", Category: CategoryInjection, Description: "HTTP/2 cleartext upgrade smuggling", VersionFlag: "--version", Enabled: true},
		{Name: "ssrfmap", Category: CategoryInjection, Description: "SSRF vulnerability scanner", VersionFlag: "--version", Enabled: true},
		{Name: "gopherus", Category: CategoryInjection, Description: "SSRF Gopher payload generator", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "arjun", Category: CategoryParams, Description: "HTTP parameter discovery", VersionFlag: "--version", Enabled: true},
		{Name: "paramspider", Category: CategoryParams, Description: "Parameter mining from web archives", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "wpscan", Category: CategoryVulnerability, Description: "WordPress vulnerability scanner", VersionFlag: "--version", Enabled: true},
		{Name: "droopescan", Category: CategoryVulnerability, Description: "CMS detection and vulnerability scanner", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "linkfinder", Category: CategoryJSAnalysis, Description: "Extract endpoints from JavaScript files", VersionFlag: "--version", Enabled: true},
		{Name: "secretfinder", Category: CategoryJSAnalysis, Description: "Find secrets in JavaScript files", VersionFlag: "--version", Enabled: true},
		{Name: "retire", Category: CategoryJSAnalysis, Description: "Detect vulnerable JavaScript libraries (retire.js)", VersionFlag: "--version", Enabled: true},
		{Name: "snyk", Category: CategoryJSAnalysis, Description: "Dependency vulnerability scanner", VersionFlag: "--version", Enabled: false},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "trufflehog", Category: CategorySecrets, Description: "Find secrets and credentials in repos", VersionFlag: "--version", Enabled: true, TimeoutSeconds: 1800},
		{Name: "gitleaks", Category: CategorySecrets, Description: "Detect secrets in git repositories", VersionFlag: "version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	for _, t := range []ToolInfo{
		{Name: "whatweb", Category: CategoryFingerprint, Description: "Web technology fingerprinting", VersionFlag: "--version", Enabled: true},
		{Name: "wappalyzer", Category: CategoryFingerprint, Description: "Technology detection (wappalyzer-cli)", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	types.DefaultRegistry.Register(ToolInfo{
		Name: "gowitness", Category: CategoryScreenshot, Description: "Web screenshot tool", VersionFlag: "version", Enabled: true,
	})

	types.DefaultRegistry.Register(ToolInfo{
		Name: "aquatone", Category: CategoryScreenshot, Description: "Visual inspection of web apps at scale", VersionFlag: "-version", Enabled: true,
	})

	for _, t := range []ToolInfo{
		{Name: "jwt_tool", Category: CategoryAuth, Description: "JWT token vulnerability tester", VersionFlag: "--version", Enabled: true},
		{Name: "corsy", Category: CategoryAuth, Description: "CORS misconfiguration scanner", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}

	// Subdomain takeover scanners
	for _, t := range []ToolInfo{
		{Name: "subjack", Category: CategoryTakeover, Description: "Subdomain takeover detection tool", VersionFlag: "-version", Enabled: true},
		{Name: "subzy", Category: CategoryTakeover, Description: "Subdomain takeover checker", VersionFlag: "version", Enabled: true},
		// nuclei is also used for takeover checks via the takeovers/ template pack
		// (registered under CategoryVulnerability above); no duplicate entry needed.
	} {
		types.DefaultRegistry.Register(t)
	}

	// Cloud CLI sync tools — presence of the binary signals the provider is configured
	for _, t := range []ToolInfo{
		{Name: "aws", Category: CategoryCloud, Description: "AWS CLI for cloud asset enumeration", VersionFlag: "--version", Enabled: true},
		{Name: "az", Category: CategoryCloud, Description: "Azure CLI for cloud asset enumeration", VersionFlag: "--version", Enabled: true},
		{Name: "gcloud", Category: CategoryCloud, Description: "GCP CLI for cloud asset enumeration", VersionFlag: "--version", Enabled: true},
	} {
		types.DefaultRegistry.Register(t)
	}
}
