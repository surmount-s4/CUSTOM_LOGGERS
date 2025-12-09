-- TimescaleDB Initialization Script
-- This script runs automatically when the container is first created

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Grant all privileges to uls_user
GRANT ALL PRIVILEGES ON DATABASE uls_detection TO uls_user;
GRANT ALL ON SCHEMA public TO uls_user;

-- Grant usage on extensions
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO uls_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO uls_user;

-- Log successful initialization
\echo 'TimescaleDB extension enabled successfully'
\echo 'User uls_user has been granted all necessary privileges'
