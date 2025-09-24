-- docker/postgres/init.sql
-- Initialize PostgreSQL database for BusiMap
-- This script runs when the PostgreSQL container starts for the first time

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE bizmap_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'bizmap_db');

-- Create user if it doesn't exist
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'bizmap_user') THEN
      
      CREATE ROLE bizmap_user LOGIN PASSWORD 'bizmap_password';
   END IF;
END
$do$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE bizmap_db TO bizmap_user;

-- Connect to the database
\c bizmap_db;

-- Enable PostGIS extension (for geospatial data)
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable full text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;

-- Grant permissions on extensions
GRANT ALL ON ALL TABLES IN SCHEMA public TO bizmap_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO bizmap_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO bizmap_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO bizmap_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO bizmap_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO bizmap_user;




