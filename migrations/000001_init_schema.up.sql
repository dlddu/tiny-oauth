-- tiny-oauth Initial Schema
-- OAuth 2.0 서버를 위한 PostgreSQL 스키마

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. oauth_clients: 클라이언트 앱 정보
CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'],
    scopes TEXT[] DEFAULT '{}',
    is_confidential BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT chk_redirect_uris_not_empty CHECK (array_length(redirect_uris, 1) > 0),
    CONSTRAINT chk_grant_types_not_empty CHECK (array_length(grant_types, 1) > 0)
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);

COMMENT ON TABLE oauth_clients IS 'OAuth 2.0 클라이언트 애플리케이션 정보';
COMMENT ON COLUMN oauth_clients.client_secret_hash IS 'bcrypt/argon2로 해시된 클라이언트 시크릿';
COMMENT ON COLUMN oauth_clients.is_confidential IS 'true: server-side app, false: public app (SPA, mobile)';

-- 2. users: 사용자 계정
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT chk_username_length CHECK (char_length(username) >= 3),
    CONSTRAINT chk_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;

COMMENT ON TABLE users IS 'OAuth 2.0 리소스 오너 (사용자) 계정';
COMMENT ON COLUMN users.password_hash IS 'bcrypt/argon2로 해시된 비밀번호';

-- 3. authorization_codes: 인가 코드 (단기 저장)
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code_hash VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    used_at TIMESTAMPTZ,
    
    CONSTRAINT chk_code_ttl CHECK (expires_at > created_at),
    CONSTRAINT chk_pkce_method CHECK (
        code_challenge_method IS NULL OR 
        code_challenge_method IN ('plain', 'S256')
    )
);

CREATE INDEX idx_auth_codes_code_hash ON authorization_codes(code_hash);
CREATE INDEX idx_auth_codes_client_id ON authorization_codes(client_id);
CREATE INDEX idx_auth_codes_user_id ON authorization_codes(user_id);
CREATE INDEX idx_auth_codes_expires_at ON authorization_codes(expires_at);

COMMENT ON TABLE authorization_codes IS 'OAuth 2.0 인가 코드 (Authorization Code)';
COMMENT ON COLUMN authorization_codes.code_hash IS 'SHA-256 해시된 인가 코드';
COMMENT ON COLUMN authorization_codes.code_challenge IS 'PKCE code_challenge 값';
COMMENT ON COLUMN authorization_codes.used_at IS '코드 사용 시간 (일회용 검증)';

-- 4. refresh_tokens: 리프레시 토큰
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    parent_token_id UUID REFERENCES refresh_tokens(id),
    
    CONSTRAINT chk_token_ttl CHECK (expires_at > created_at)
);

CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(user_id, client_id) 
    WHERE revoked_at IS NULL;

COMMENT ON TABLE refresh_tokens IS 'OAuth 2.0 리프레시 토큰';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 해시된 리프레시 토큰';
COMMENT ON COLUMN refresh_tokens.parent_token_id IS 'Token Rotation 시 이전 토큰 참조';

-- 5. token_blacklist: 토큰 블랙리스트 (로그아웃용)
CREATE TABLE token_blacklist (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    reason VARCHAR(255)
);

CREATE INDEX idx_token_blacklist_jti ON token_blacklist(jti);
CREATE INDEX idx_token_blacklist_expires_at ON token_blacklist(expires_at);

COMMENT ON TABLE token_blacklist IS 'JWT Access Token 블랙리스트 (로그아웃/폐기)';
COMMENT ON COLUMN token_blacklist.jti IS 'JWT ID (고유 식별자)';

-- 6. audit_logs: 감사 로그 (선택)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    client_id UUID REFERENCES oauth_clients(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_client_id ON audit_logs(client_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

COMMENT ON TABLE audit_logs IS '보안 감사 로그';
COMMENT ON COLUMN audit_logs.event_type IS 'login, logout, token_issued, token_revoked, etc.';

-- Function: Updated At Trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply Updated At Triggers
CREATE TRIGGER trigger_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
