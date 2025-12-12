-- TimescaleDB Initialization Script
-- This script runs automatically when the container is first created

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Grant all privileges to admin user
GRANT ALL PRIVILEGES ON DATABASE uls_detection TO admin;
GRANT ALL ON SCHEMA public TO admin;

-- Grant usage on extensions
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO admin;

-- Log successful initialization
\echo 'TimescaleDB extension enabled successfully'
\echo 'User admin has been granted all necessary privileges'
