-- tiny-oauth Initial Schema Rollback

-- Drop triggers first
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
DROP TRIGGER IF EXISTS trigger_oauth_clients_updated_at ON oauth_clients;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order (respecting foreign key dependencies)
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS token_blacklist;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS oauth_clients;

-- Drop extension (optional, may be used by other schemas)
-- DROP EXTENSION IF EXISTS "uuid-ossp";
