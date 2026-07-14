-- Rayyan ASM — PostgreSQL initialization
-- This runs once when the container is first created.

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- trigram full-text search
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive text

-- Create indexes that GORM won't auto-generate (post-migration)
-- These are created by the init script so they exist right after first migration.

-- Performance indexes
-- (actual table creation happens via GORM AutoMigrate at startup)

-- Set timezone
SET timezone = 'UTC';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE rayyan_asm TO rayyan;

\echo 'Rayyan ASM database initialized'
