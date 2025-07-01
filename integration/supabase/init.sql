-- Create necessary roles and users for Supabase
CREATE ROLE anon nologin noinherit;
CREATE ROLE authenticated nologin noinherit;
CREATE ROLE service_role nologin noinherit bypassrls;

-- Create authenticator role that can switch to other roles
CREATE ROLE authenticator noinherit login password 'postgres';
GRANT anon, authenticated, service_role TO authenticator;

-- Create supabase_admin user with superuser privileges
CREATE ROLE supabase_admin noinherit createrole login password 'postgres' superuser;

-- Create supabase_auth_admin user with all privileges on public schema
CREATE ROLE supabase_auth_admin noinherit login password 'postgres';
GRANT ALL PRIVILEGES ON DATABASE postgres TO supabase_admin, supabase_auth_admin;

-- Grant full ownership and privileges on public schema
GRANT ALL ON SCHEMA public TO supabase_auth_admin;
GRANT CREATE ON SCHEMA public TO supabase_auth_admin;
ALTER SCHEMA public OWNER TO supabase_auth_admin;

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

-- Grant permissions on public schema
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role;

-- Grant schema permissions to auth admin
GRANT ALL ON SCHEMA public TO supabase_auth_admin;
GRANT ALL ON ALL TABLES IN SCHEMA public TO supabase_auth_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO supabase_auth_admin;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO supabase_auth_admin;

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role, supabase_auth_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role, supabase_auth_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role, supabase_auth_admin;