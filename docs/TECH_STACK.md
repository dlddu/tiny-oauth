# tiny-oauth 기술 스택

## 개요

개인 인프라에서 사용할 OAuth 2.0 서버의 기술 스택 선정 문서입니다.

## 최종 선정 기술

| 구성요소 | 선정 기술 | 선정 이유 |
|---------|----------|----------|
| 언어 | Go 1.22+ | Kubernetes 친화적, 작은 바이너리, 강력한 표준 라이브러리 |
| 데이터베이스 | PostgreSQL 15+ | 프로덕션 검증됨, ACID 보장, 풍부한 데이터 타입 지원 |
| 토큰 | JWT (RS256) | Stateless 검증, 비대칭 암호화로 보안 강화 |
| 캐시 | Redis (선택) | 토큰 블랙리스트, Rate Limiting용 |

---

## 1. 프로그래밍 언어: Go

### 후보 비교

| 기준 | Go | Node.js |
|------|-----|---------|
| K8s 통합 | 네이티브 (k8s.io/client-go) | 외부 라이브러리 필요 |
| 바이너리 크기 | 5-15MB (단일 바이너리) | 런타임 + node_modules 필요 |
| 동시성 모델 | Goroutines (경량) | Event Loop (콜백 기반) |
| 타입 안정성 | 정적 타입 | TypeScript로 보완 필요 |
| 개발 속도 | 중간 | 빠름 |
| 프로덕션 레퍼런스 | Ory Hydra, Dex | Keycloak(Java), Auth0 |

### 선정 이유

1. **Kubernetes 네이티브**: k8s.io/client-go 공식 라이브러리로 Kubernetes API와 직접 통합
2. **단일 바이너리 배포**: Docker 이미지 크기 최소화 (scratch 베이스 이미지 사용 가능)
3. **표준 라이브러리**: crypto, net/http 등 보안 및 네트워크 기능이 풍부
4. **검증된 OAuth 구현**: Ory Hydra가 Go로 작성되어 참조 가능
5. **수평 확장성**: Stateless 설계와 Goroutines로 고성능 동시 처리

### 주요 라이브러리 계획

- net/http (표준 HTTP 서버)
- golang-jwt/jwt/v5 (JWT 처리)
- jackc/pgx/v5 (PostgreSQL 드라이버)
- redis/go-redis/v9 (Redis 클라이언트, 선택)
- golang-migrate/migrate (DB 마이그레이션)

---

## 2. 데이터베이스: PostgreSQL

### 선정 이유

1. **프로덕션 검증**: 대규모 서비스에서 검증된 안정성
2. **ACID 보장**: 트랜잭션 무결성 보장
3. **풍부한 데이터 타입**: UUID, ARRAY, JSONB, TIMESTAMPTZ 지원
4. **인덱스 성능**: B-tree, Hash, GIN 등 다양한 인덱스 지원
5. **확장성**: Connection pooling (PgBouncer), Read replica 지원

### 버전 선택

- **PostgreSQL 15+**: 성능 개선, MERGE 문 지원
- 로컬 개발: Docker로 PostgreSQL 컨테이너 사용
- 프로덕션: Kubernetes StatefulSet 또는 관리형 서비스

---

## 3. 토큰 전략: JWT (RS256)

### 알고리즘 선택

| 알고리즘 | 타입 | 사용 사례 |
|---------|------|----------|
| HS256 | 대칭키 | 단일 서비스 (비권장) |
| RS256 | 비대칭키 | 분산 시스템 (권장) |
| ES256 | 비대칭키 | 모바일 앱 (작은 서명) |

**RS256 선택 이유**:
- Private key는 OAuth 서버만 보유
- Public key로 어느 서비스에서나 토큰 검증 가능
- 키 유출 시에도 토큰 위조 불가 (private key 필요)

### 토큰 만료 정책

| 토큰 타입 | TTL | 저장소 | 비고 |
|----------|-----|--------|------|
| Access Token | 15분 | 없음 (JWT) | Stateless 검증 |
| Refresh Token | 7일 | PostgreSQL | 해시 저장, Rotation 적용 |
| Authorization Code | 10분 | PostgreSQL | 일회용, 해시 저장 |

### 키 관리 전략

1. RSA 2048-bit 키 쌍 생성
2. Private key: Kubernetes Secret으로 관리
3. Public key: /.well-known/jwks.json 엔드포인트로 제공
4. 키 순환: 6개월마다 새 키 쌍 추가, 이전 키 유지 (검증용)

---

## 4. 캐시: Redis (선택)

### 사용 목적

1. **토큰 블랙리스트**
   - 로그아웃 시 access token 즉시 무효화
   - TTL 자동 만료 (토큰 만료 시간과 동일)

2. **Rate Limiting**
   - 로그인 시도 제한 (IP/계정별)
   - API 호출 제한

### 초기 단계 전략

MVP에서는 Redis 없이 시작:
- 토큰 블랙리스트: DB 조회로 대체
- Rate Limiting: 애플리케이션 레벨로 구현

Redis는 성능 병목 발생 시 도입 예정.

---

## 5. 프로젝트 구조

```
tiny-oauth/
├── cmd/
│   └── server/
│       └── main.go           # 애플리케이션 진입점
├── internal/
│   ├── config/               # 설정 관리
│   ├── handler/              # HTTP 핸들러
│   ├── repository/           # 데이터 접근 계층
│   ├── service/              # 비즈니스 로직
│   └── domain/               # 도메인 모델
├── migrations/               # DB 마이그레이션 파일
├── docs/                     # 문서
├── scripts/                  # 유틸리티 스크립트
├── docker-compose.yml        # 로컬 개발 환경
├── Dockerfile                # 컨테이너 빌드
├── go.mod                    # Go 모듈 정의
└── README.md                 # 프로젝트 설명
```

---

## 6. 보안 고려사항

### 필수 구현

- 모든 secret/token 해시 저장 (bcrypt, argon2)
- HTTPS 강제 (프로덕션)
- CORS 정책 설정
- Rate Limiting
- Input validation

### 권장 사항

- PKCE (Proof Key for Code Exchange) 지원
- 보안 헤더 (CSP, HSTS, X-Frame-Options)
- 감사 로깅 (audit log)

---

## 참고 자료

- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [Ory Hydra (Go OAuth Server)](https://github.com/ory/hydra)
- [Auth0 Token Best Practices](https://auth0.com/docs/secure/tokens/token-best-practices)
- [PostgreSQL 공식 문서](https://www.postgresql.org/docs/)
