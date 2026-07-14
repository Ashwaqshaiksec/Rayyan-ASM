-- 036_backfill_service_host_id.sql
--
-- Data backfill, not a schema change. services.host_id has existed all
-- along, but three scan pipelines (discovery engine's port/service stage,
-- the standalone "port" scan job, and the toolrunner nmap/naabu/rustscan/
-- masscan workflows) only ever wrote services.host_ref (the IP as text)
-- and left host_id NULL. The host-detail page's service list filters
-- strictly on host_id, so every service created before the code fix is
-- still invisible there even though the row exists.
--
-- This does the same match those pipelines now do at write time: link a
-- service to the hosts row with the same org_id + ip. Only touches rows
-- that are actually missing the link, so it's safe to re-run.
--
-- Postgres:
UPDATE services s
SET host_id = h.id
FROM hosts h
WHERE s.host_id IS NULL
  AND s.host_ref = h.ip
  AND s.org_id = h.org_id;

-- SQLite (dev/test DB) doesn't support UPDATE ... FROM before 3.33 and
-- Rayyan's sqlite driver targets an older dialect — use a correlated
-- subquery instead. Harmless no-op on Postgres if run by mistake, since
-- the rows it would touch are already fixed by the statement above.
UPDATE services
SET host_id = (
    SELECT h.id FROM hosts h
    WHERE h.ip = services.host_ref
      AND h.org_id = services.org_id
)
WHERE host_id IS NULL
  AND EXISTS (
    SELECT 1 FROM hosts h
    WHERE h.ip = services.host_ref
      AND h.org_id = services.org_id
  );
