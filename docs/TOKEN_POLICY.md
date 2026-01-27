# tiny-oauth 토큰 정책

## 개요

JWT 기반 OAuth 2.0 토큰 관리 정책 및 보안 전략 문서입니다.

---

## 1. 토큰 타입별 정책

### 1.1 Access Token

| 항목 | 값 | 설명 |
|------|-----|------|
| 형식 | JWT | Stateless 검증 가능 |
| 알고리즘 | RS256 | RSA 2048-bit 비대칭 키 |
| TTL | 15분 | 짧은 수명으로 보안 강화 |
| 저장소 | 없음 | 클라이언트 메모리에만 보관 |

**JWT Payload 구조**:
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567000,
  "jti": "unique-token-id",
  "scope": "read write",
  "client_id": "client-uuid"
}
```

**클레임 설명**:
- `iss`: 토큰 발급자 (OAuth 서버 URL)
- `sub`: 사용자 식별자 (user.id)
- `aud`: 대상 클라이언트 (client_id)
- `exp`: 만료 시간 (Unix timestamp)
- `iat`: 발급 시간
- `jti`: JWT ID (블랙리스트용 고유 ID)
- `scope`: 허용된 권한 범위
- `client_id`: 클라이언트 애플리케이션 ID

### 1.2 Refresh Token

| 항목 | 값 | 설명 |
|------|-----|------|
| 형식 | Opaque | 랜덤 문자열 (32 bytes) |
| TTL | 7일 | 재인증 주기 |
| 저장소 | PostgreSQL | 해시로 저장 |
| Rotation | 필수 | 사용 시 새 토큰 발급 |

**보안 정책**:
1. **해시 저장**: SHA-256 해시로 저장, 원본은 발급 시에만 반환
2. **Token Rotation**: 사용할 때마다 새 토큰 발급, 기존 토큰 폐기
3. **Family Tracking**: parent_token_id로 토큰 계보 추적
4. **Reuse Detection**: 폐기된 토큰 재사용 시 전체 토큰 패밀리 폐기

### 1.3 Authorization Code

| 항목 | 값 | 설명 |
|------|-----|------|
| 형식 | Opaque | 랜덤 문자열 (32 bytes) |
| TTL | 10분 | 매우 짧은 수명 |
| 사용 | 일회용 | 교환 후 즉시 폐기 |
| PKCE | 권장 | Public 클라이언트 필수 |

---

## 2. 키 관리

### 2.1 RSA 키 쌍 생성

```bash
# Private Key 생성 (2048-bit RSA)
openssl genrsa -out keys/private.pem 2048

# Public Key 추출
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# JWK 형식으로 변환 (jose 라이브러리 사용)
# 또는 Go 코드에서 동적 생성
```

### 2.2 키 저장 전략

**개발 환경**:
- 파일 시스템에 저장 (`keys/` 디렉토리)
- `.gitignore`에 추가하여 커밋 방지

**프로덕션 환경**:
```yaml
# Kubernetes Secret
apiVersion: v1
kind: Secret
metadata:
  name: oauth-jwt-keys
type: Opaque
data:
  private.pem: <base64-encoded>
  public.pem: <base64-encoded>
```

### 2.3 키 순환 (Key Rotation)

| 단계 | 작업 | 설명 |
|------|------|------|
| 1 | 새 키 쌍 생성 | kid (Key ID) 포함 |
| 2 | JWKS 업데이트 | 새 키 추가, 기존 키 유지 |
| 3 | 신규 발급 전환 | 새 키로 토큰 서명 시작 |
| 4 | 유예 기간 | 기존 토큰 만료까지 대기 |
| 5 | 이전 키 제거 | JWKS에서 삭제 |

**순환 주기**: 6개월 권장

---

## 3. JWKS 엔드포인트

### 3.1 /.well-known/jwks.json

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2024-01",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### 3.2 캐싱 정책

- **Cache-Control**: `max-age=3600` (1시간)
- **클라이언트 캐싱**: kid 기반으로 캐시 무효화

---

## 4. 토큰 폐기 (Revocation)

### 4.1 폐기 사유

| 사유 | 처리 방법 |
|------|----------|
| 로그아웃 | Access Token: 블랙리스트 추가, Refresh Token: DB에서 revoke |
| 비밀번호 변경 | 해당 사용자의 모든 토큰 폐기 |
| 의심스러운 활동 | 전체 토큰 패밀리 폐기 |
| 클라이언트 폐기 | 해당 클라이언트의 모든 토큰 폐기 |

### 4.2 블랙리스트 관리

```sql
-- 블랙리스트 추가
INSERT INTO token_blacklist (jti, user_id, expires_at, reason)
VALUES ($1, $2, $3, 'logout');

-- 블랙리스트 확인
SELECT EXISTS(
    SELECT 1 FROM token_blacklist 
    WHERE jti = $1 AND expires_at > NOW()
);
```

### 4.3 만료 토큰 정리

```sql
-- 크론 작업: 매일 실행
DELETE FROM authorization_codes WHERE expires_at < NOW();
DELETE FROM refresh_tokens WHERE expires_at < NOW();
DELETE FROM token_blacklist WHERE expires_at < NOW();
```

---

## 5. PKCE (Proof Key for Code Exchange)

### 5.1 지원 방식

| 메서드 | 설명 | 권장 |
|--------|------|------|
| plain | code_verifier == code_challenge | 비권장 |
| S256 | BASE64URL(SHA256(code_verifier)) | 권장 |

### 5.2 검증 흐름

1. **인가 요청**: code_challenge, code_challenge_method 전송
2. **저장**: authorization_codes 테이블에 저장
3. **토큰 교환**: code_verifier 전송
4. **검증**: 
   - plain: `code_verifier == stored_challenge`
   - S256: `BASE64URL(SHA256(code_verifier)) == stored_challenge`

### 5.3 적용 정책

- **Confidential Client**: PKCE 선택
- **Public Client**: PKCE 필수

---

## 6. Rate Limiting

### 6.1 엔드포인트별 제한

| 엔드포인트 | 제한 | 기준 |
|-----------|------|------|
| /authorize | 60/분 | IP |
| /token | 30/분 | Client ID |
| /userinfo | 100/분 | Access Token |

### 6.2 로그인 시도 제한

- **계정당**: 5회 실패 시 15분 잠금
- **IP당**: 100회/시간 초과 시 1시간 차단

---

## 7. 보안 체크리스트

### 발급 시

- [ ] HTTPS 필수 (프로덕션)
- [ ] redirect_uri 검증 (등록된 URI만 허용)
- [ ] state 파라미터 검증 (CSRF 방지)
- [ ] PKCE 검증 (Public 클라이언트)
- [ ] scope 검증 (허용된 범위만)

### 검증 시

- [ ] 서명 검증 (RS256)
- [ ] 만료 시간 확인 (exp)
- [ ] 발급자 확인 (iss)
- [ ] 대상자 확인 (aud)
- [ ] 블랙리스트 확인 (jti)

### 저장 시

- [ ] 토큰 해시 저장 (원본 저장 금지)
- [ ] 민감 정보 암호화
- [ ] 로그에 토큰 출력 금지

---

## 참고 자료

- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7519 - JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7009 - Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
