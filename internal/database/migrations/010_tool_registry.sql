-- Migration: 0XX_tool_registry.sql
-- Adds a persistent tool_registry table for storing tool state across restarts.
-- The authoritative runtime state lives in memory (toolrunner.DefaultRegistry);
-- this table provides a persistent audit trail and allows admins to pre-configure
-- enabled/disabled states that survive server restarts.

CREATE TABLE IF NOT EXISTS tool_registry (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    category    TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    binary_path TEXT        NOT NULL DEFAULT '',
    version     TEXT        NOT NULL DEFAULT '',
    status      TEXT        NOT NULL DEFAULT 'missing'
                            CHECK (status IN ('installed', 'missing', 'wrong_version')),
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_run_ok BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for category-based listing (used by the grouped list endpoint)
CREATE INDEX IF NOT EXISTS idx_tool_registry_category ON tool_registry (category);

-- Index for fast single-tool lookup by name
CREATE INDEX IF NOT EXISTS idx_tool_registry_name ON tool_registry (name);

-- Trigger to keep updated_at current on every row update
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tool_registry_updated_at ON tool_registry;
CREATE TRIGGER trg_tool_registry_updated_at
    BEFORE UPDATE ON tool_registry
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Seed the known tools so that admin-configured enable/disable persists across
-- server restarts. The runtime registry merges DB state at startup.
-- ON CONFLICT DO NOTHING ensures idempotency (safe to re-run).

INSERT INTO tool_registry (name, category, description, enabled) VALUES
    -- Subdomain
    ('subfinder',      'subdomain',    'Passive subdomain enumeration',              true),
    ('amass',          'subdomain',    'In-depth subdomain enumeration',             true),
    ('assetfinder',    'subdomain',    'Find domains and subdomains',                true),
    ('findomain',      'subdomain',    'Subdomain finder',                           true),
    ('theHarvester',   'subdomain',    'OSINT email/subdomain harvester',            true),
    ('sublist3r',      'subdomain',    'Fast subdomains enumeration tool',           true),
    ('subbrute',       'subdomain',    'DNS brute-force subdomain scanner',          true),
    ('SubDomainizer',  'subdomain',    'Find subdomains in JS files',                false),
    -- DNS
    ('dnsx',           'dns',          'Fast DNS toolkit',                           true),
    ('dnsrecon',       'dns',          'DNS enumeration tool',                       true),
    ('dnsenum',        'dns',          'Multithreaded DNS enumeration',              true),
    ('dnstwist',       'dns',          'Domain name permutation engine',             true),
    -- Network
    ('nmap',           'network',      'Network mapper',                             true),
    ('naabu',          'network',      'Fast port scanner',                          true),
    ('rustscan',       'network',      'Ultra-fast port scanner',                    true),
    ('masscan',        'network',      'Mass IP port scanner',                       true),
    -- Web
    ('httpx',          'web',          'HTTP probe toolkit',                         true),
    ('katana',         'web',          'Next-gen web crawler',                       true),
    ('hakrawler',      'web',          'Web crawler with JS parsing',                true),
    ('gau',            'web',          'Get All URLs from open archives',            true),
    ('waybackurls',    'web',          'Fetch Wayback Machine URLs',                 true),
    -- Content Discovery
    ('ffuf',           'content',      'Fast web fuzzer',                            true),
    ('feroxbuster',    'content',      'Recursive content discovery',                true),
    ('gobuster',       'content',      'Directory/DNS/vhost brute-forcer',           true),
    ('dirsearch',      'content',      'URL fuzzing tool',                           true),
    -- Vulnerability
    ('nuclei',         'vulnerability','Template-based vulnerability scanner',       true),
    ('nikto',          'vulnerability','Web server scanner',                         true),
    ('testssl.sh',     'vulnerability','TLS/SSL testing',                            true),
    -- WAF
    ('wafw00f',        'waf',          'WAF fingerprinting tool',                    true),
    -- SMB
    ('smbclient',      'smb',          'SMB share client',                           true),
    ('enum4linux-ng',  'smb',          'SMB/Samba enumeration',                      true),
    ('crackmapexec',   'smb',          'Network protocol attacks',                   false),
    -- Origin IP
    ('cloudflair',     'origin_ip',    'Find origin IPs behind CDN',                 true),
    ('hakoriginfinder','origin_ip',    'Find origin server for CDN hosts',           true),
    ('cloakquest3r',   'origin_ip',    'Uncover real IPs behind Cloudflare',         true)
ON CONFLICT (name) DO NOTHING;
