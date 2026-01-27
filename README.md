# tiny-oauth

개인 인프라에서 사용할 OAuth 2.0 서버입니다.

## 기술 스택

- **언어**: Go 1.22+
- **데이터베이스**: PostgreSQL 15+
- **토큰**: JWT (RS256)
- **캐시**: Redis (선택)

자세한 내용은 [기술 스택 문서](docs/TECH_STACK.md)를 참조하세요.

## 빠른 시작

### 1. 사전 요구사항

- Go 1.22+
- Docker & Docker Compose
- OpenSSL (키 생성용)

### 2. 설정

```bash
# 저장소 클론
git clone https://github.com/dlddu/tiny-oauth.git
cd tiny-oauth

# 환경 변수 설정
cp .env.example .env

# JWT 키 생성
./scripts/generate-keys.sh

# 개발 환경 실행
docker-compose up -d
```

### 3. 실행

```bash
# Go 모듈 다운로드
go mod download

# 서버 실행
go run ./cmd/server

# 또는 빌드 후 실행
go build -o server ./cmd/server
./server
```

### 4. 확인

```bash
# Health check
curl http://localhost:8080/health

# OpenID Configuration
curl http://localhost:8080/.well-known/openid-configuration
```

## 프로젝트 구조

```
tiny-oauth/
├── cmd/server/          # 애플리케이션 진입점
├── internal/
│   ├── config/          # 설정 관리
│   ├── domain/          # 도메인 모델
│   ├── handler/         # HTTP 핸들러
│   ├── repository/      # 데이터 접근
│   └── service/         # 비즈니스 로직
├── migrations/          # DB 마이그레이션
├── docs/                # 문서
└── scripts/             # 유틸리티 스크립트
```

## 문서

- [기술 스택](docs/TECH_STACK.md) - 기술 선정 근거
- [토큰 정책](docs/TOKEN_POLICY.md) - JWT 및 토큰 관리 정책

## 데이터베이스 스키마

```
oauth_clients        - 클라이언트 앱 정보
users                - 사용자 계정
authorization_codes  - 인가 코드 (단기 저장)
refresh_tokens       - 리프레시 토큰
token_blacklist      - 토큰 블랙리스트
audit_logs           - 감사 로그
```

스키마 상세는 [migrations/000001_init_schema.up.sql](migrations/000001_init_schema.up.sql)을 참조하세요.

## 라이선스

MIT
