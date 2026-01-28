# Testing Guide

이 문서는 tiny-oauth 프로젝트의 테스트 전략과 실행 방법을 설명합니다.

## 테스트 구조

프로젝트는 TDD(Test-Driven Development) 방식으로 개발되며, 다음과 같은 테스트 레벨을 포함합니다:

### 1. Unit Tests (단위 테스트)

- **위치**: 각 패키지의 `*_test.go` 파일
- **목적**: 개별 함수/메서드의 정확성 검증
- **특징**: Mock 객체 사용, 외부 의존성 없음

**예시**:
- `internal/service/oauth_service_test.go` - OAuth 서비스 로직
- `internal/service/jwt_service_test.go` - JWT 생성/검증
- `internal/handler/token_handler_test.go` - HTTP 핸들러

### 2. Integration Tests (통합 테스트)

- **위치**: `*_integration_test.go` 파일
- **목적**: 여러 컴포넌트가 함께 작동하는지 검증
- **특징**: 실제 구현체 사용, DB 연결 필요할 수 있음

**예시**:
- `internal/handler/token_handler_integration_test.go` - 전체 토큰 발급 플로우

### 3. Repository Tests (리포지토리 테스트)

- **위치**: `internal/repository/*_test.go`
- **목적**: 데이터베이스 CRUD 작업 검증
- **특징**: 실제 PostgreSQL 연결 필요

## 테스트 실행

### 모든 테스트 실행

```bash
make test
# 또는
go test -v -race ./...
```

### 단위 테스트만 실행 (통합 테스트 제외)

```bash
make test-short
# 또는
go test -v -short ./...
```

### 특정 패키지 테스트

```bash
# Service 테스트만
go test -v ./internal/service/...

# Handler 테스트만
go test -v ./internal/handler/...

# Repository 테스트만
go test -v ./internal/repository/...
```

### 특정 테스트 함수 실행

```bash
go test -v -run TestOAuthService_ClientCredentialsGrant_Success ./internal/service/...
```

### 커버리지와 함께 실행

```bash
make test-coverage
# 또는
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
go tool cover -html=coverage.out -o coverage.html
```

## 테스트 케이스 설계

### Client Credentials Grant 테스트

#### 정상 케이스 (Happy Path)

1. ✅ **유효한 클라이언트 인증으로 토큰 발급**
   - 정상적인 client_id와 client_secret
   - 허용된 scope 요청
   - 예상: 200 OK, JWT 토큰 반환

2. ✅ **Basic Auth를 통한 토큰 발급**
   - Authorization: Basic {base64(client_id:client_secret)}
   - 예상: 200 OK, JWT 토큰 반환

3. ✅ **POST body를 통한 토큰 발급**
   - client_id와 client_secret를 body에 포함
   - 예상: 200 OK, JWT 토큰 반환

4. ✅ **빈 scope 요청 (모든 scope 허용)**
   - scope 파라미터 없음
   - 예상: 클라이언트의 모든 허용 scope 부여

#### 에러 케이스 (Error Cases)

1. ✅ **잘못된 client_id**
   - 예상: 401 Unauthorized, error: "invalid_client"

2. ✅ **잘못된 client_secret**
   - 예상: 401 Unauthorized, error: "invalid_client"

3. ✅ **지원되지 않는 grant_type**
   - 예상: 400 Bad Request, error: "unsupported_grant_type"

4. ✅ **허용되지 않은 grant_type (클라이언트 설정)**
   - 클라이언트가 client_credentials를 지원하지 않음
   - 예상: 400 Bad Request, error: "unauthorized_client"

5. ✅ **허용되지 않은 scope**
   - 클라이언트에 할당되지 않은 scope 요청
   - 예상: 400 Bad Request, error: "invalid_scope"

6. ✅ **Public 클라이언트로 client_credentials 요청**
   - IsConfidential = false
   - 예상: 401 Unauthorized, error: "invalid_client"

7. ✅ **클라이언트 인증 정보 누락**
   - Basic Auth 없고 body에도 없음
   - 예상: 401 Unauthorized, error: "invalid_client"

8. ✅ **grant_type 파라미터 누락**
   - 예상: 400 Bad Request, error: "invalid_request"

9. ✅ **잘못된 HTTP 메서드 (GET 등)**
   - 예상: 405 Method Not Allowed

#### 엣지 케이스 (Edge Cases)

1. ✅ **빈 scope 문자열**
   - scope=""
   - 예상: 모든 허용 scope 부여

2. ✅ **중복된 scope**
   - scope="read read write"
   - 예상: 중복 제거 후 처리

3. ✅ **대소문자 구분 (scope)**
   - 구현에 따라 다름 (일반적으로 대소문자 구분)

### JWT 토큰 검증

1. ✅ **올바른 알고리즘 (RS256)**
2. ✅ **필수 클레임 포함**
   - sub (client_id)
   - iss (issuer)
   - exp (expiration)
   - iat (issued at)
   - jti (JWT ID, 고유값)
   - scope
3. ✅ **서명 검증**
4. ✅ **만료 시간 검증**
5. ✅ **JTI 고유성**

## Mock 객체

테스트에서는 다음 Mock 객체들을 사용합니다:

### MockClientRepository

```go
type MockClientRepository struct {
    GetByClientIDFunc func(ctx context.Context, clientID string) (*domain.Client, error)
}
```

### MockOAuthService

```go
type MockOAuthService struct {
    ClientCredentialsGrantFunc func(clientID, clientSecret string, scopes []string) (*TokenResponse, error)
}
```

### MockJWTService

```go
type MockJWTService struct {
    GenerateAccessTokenFunc func(clientID string, scopes []string, expiresAt time.Time) (string, error)
}
```

## 테스트 환경 설정

### 로컬 개발

```bash
# 1. PostgreSQL 시작
make db-up

# 2. RSA 키 생성
make generate-keys

# 3. 환경 변수 설정
cp .env.example .env

# 4. 테스트 실행
make test
```

### CI/CD (GitHub Actions)

`.github/workflows/test.yml` 파일에 정의되어 있습니다:

- PostgreSQL 서비스 컨테이너 사용
- RSA 키 자동 생성
- 커버리지 리포트 생성
- Codecov 업로드

## OAuth 2.1 보안 요구사항

테스트는 다음 OAuth 2.1 보안 요구사항을 검증합니다:

1. ✅ **Client Credentials는 Confidential Client만 사용**
2. ✅ **클라이언트 인증 필수**
3. ✅ **Scope 검증**
4. ✅ **JWT는 RS256 사용 (비대칭 키)**
5. ✅ **토큰 응답에 Cache-Control: no-store 헤더**
6. ✅ **토큰 응답에 Pragma: no-cache 헤더**
7. ✅ **에러 응답은 RFC 6749 형식 준수**

## 에러 응답 형식

모든 OAuth 에러는 다음 형식을 따릅니다:

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### HTTP 상태 코드 매핑

- `invalid_client`: 401 Unauthorized
- `invalid_request`: 400 Bad Request
- `invalid_scope`: 400 Bad Request
- `unauthorized_client`: 400 Bad Request
- `unsupported_grant_type`: 400 Bad Request

## 커버리지 목표

- **전체 커버리지**: 최소 60%
- **비즈니스 로직**: 최소 80%
- **핸들러**: 최소 70%
- **리포지토리**: 최소 60%

## 참고 자료

- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-08)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7519 - JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [Go Testing Package](https://pkg.go.dev/testing)
