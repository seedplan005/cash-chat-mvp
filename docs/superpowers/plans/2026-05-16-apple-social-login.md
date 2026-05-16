# Apple Social Login Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add backend Sign in with Apple support for the CashChat iOS app using Apple authorization code exchange and validated Apple `id_token` claims.

**Architecture:** Mirror the current Google OAuth callback shape, but replace Google user info lookup with Apple token exchange plus Apple `id_token` validation. Keep CashChat user lookup, guest upgrade, point initialization, JWT issuance, and refresh token issuance in the existing auth service path as much as possible.

**Tech Stack:** Kotlin, Spring Boot MVC, Spring Data JPA, Spring `RestClient`, JWT/JWK validation, Kotest, Mockito, MockMvc.

---

## Files

- Modify: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/web/controller/AuthController.kt`
- Modify: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/service/AuthService.kt`
- Modify: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/persistence/entity/AuthProviderType.kt`
- Modify: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/oauth/properties/OAuthProperties.kt`
- Modify: `apps/backend/src/main/resources/application.yaml`
- Modify: `apps/backend/src/main/resources/application-dev.yaml`
- Modify: `apps/backend/src/main/resources/application-prod.yaml`
- Modify: `apps/backend/.env.example`
- Create: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/web/request/AppleOAuthCallbackRequest.kt`
- Create: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleClientSecretGenerator.kt`
- Create: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleTokenClient.kt`
- Create: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleIdTokenValidator.kt`
- Create: `apps/backend/src/main/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleUserInfoExtractor.kt`
- Modify: `apps/backend/src/test/kotlin/com/wnl/cashchat/api/domain/auth/web/controller/AuthControllerTest.kt`
- Modify: `apps/backend/src/test/kotlin/com/wnl/cashchat/api/domain/auth/service/AuthServiceTest.kt`
- Create: `apps/backend/src/test/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleClientSecretGeneratorTest.kt`
- Create: `apps/backend/src/test/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleTokenClientTest.kt`
- Create: `apps/backend/src/test/kotlin/com/wnl/cashchat/api/domain/auth/oauth/apple/AppleIdTokenValidatorTest.kt`

## Task 1: Contract Tests

- [ ] Add `AppleOAuthCallbackRequest` with `authorizationCode` as a non-blank required field and `identityToken`, `fullName`, `deviceToken` as optional fields.
- [ ] Add `AuthController` MockMvc coverage for `POST /api/auth/callback/apple` returning `AuthResponse`.
- [ ] Add validation coverage for blank or missing `authorizationCode`.
- [ ] Verify controller tests assert that Apple login delegates to the auth service with Apple provider semantics.
- [ ] Run `./gradlew test --tests "*AuthControllerTest"` from `apps/backend` (Windows: `.\gradlew.bat test --tests "*AuthControllerTest"`).

## Task 2: Provider And Configuration Model

- [ ] Add `APPLE` to `AuthProviderType`.
- [ ] Extend auth OAuth configuration with Apple-specific fields: client id, team id, key id, private key source, token URI, JWKS URI, and redirect URI when required.
- [ ] Add safe placeholder values to backend example configuration files.
- [ ] Confirm no real Apple private key material is committed.
- [ ] Run `./gradlew test --tests "*AuthServiceTest"` from `apps/backend` to catch compile failures before service integration (Windows: `.\gradlew.bat test --tests "*AuthServiceTest"`).

## Task 3: Apple Client Secret Generator

- [ ] Implement client secret JWT generation using Apple Team ID, Key ID, client id, and private key.
- [ ] Keep the generated client secret and private key out of logs.
- [ ] Add tests for JWT header `kid` and expected claims.
- [ ] Add tests for missing or malformed private key configuration.
- [ ] Decide in implementation whether to generate per request or cache until near expiration.

## Task 4: Apple Token Exchange Client

- [ ] Implement Apple authorization code exchange against `https://appleid.apple.com/auth/token`.
- [ ] Send `client_id`, generated `client_secret`, `code`, `grant_type=authorization_code`, and configured `redirect_uri` when required.
- [ ] Require `id_token` in the mapped token response.
- [ ] Convert Apple HTTP failures, network failures, and malformed responses into `OAuthException`.
- [ ] Add token client tests for success, Apple rejection, network failure, and missing `id_token`.

## Task 5: Apple ID Token Validation

- [ ] Implement JWKS retrieval and key selection by token header `kid`.
- [ ] Validate token signature, issuer `https://appleid.apple.com`, configured audience, expiration, and required `sub`.
- [ ] Add tests using generated test keys for valid token, wrong audience, expired token, missing subject, and unknown key id.
- [ ] Ensure validation errors do not include the raw token in exception messages or logs.

## Task 6: User Mapping And Auth Service Integration

- [ ] Map validated Apple claims to `OAuthUserInfo` with provider id from `sub` and email from `email` when present.
- [ ] Preserve existing stored email/name for returning users when Apple omits optional values.
- [ ] Reuse the current guest upgrade behavior for matching `deviceToken` and provider `NONE`.
- [ ] Ensure upgraded guest users become `MEMBER` and have `deviceToken` cleared.
- [ ] Ensure existing Apple users receive new CashChat access and refresh tokens without duplicate user creation.
- [ ] Ensure point initialization still runs through the existing auth response path.

## Task 7: Endpoint Implementation

- [ ] Add `POST /api/auth/callback/apple` to `AuthController`.
- [ ] Return the existing `AuthResponse` shape.
- [ ] Confirm Google login remains on `POST /api/auth/callback/google` and is not regressed.
- [ ] Ensure logs avoid authorization code, Apple tokens, generated client secret, and private key values.

## Task 8: Verification

- [ ] Run `./gradlew test --tests "*AuthControllerTest" --tests "*AuthServiceTest" --tests "*Apple*Test"` from `apps/backend` (Windows: `.\gradlew.bat test --tests "*AuthControllerTest" --tests "*AuthServiceTest" --tests "*Apple*Test"`).
- [ ] Run existing Google OAuth tests.
- [ ] Run full backend test suite when local environment allows it.
- [ ] Inspect `git diff` for unrelated changes before completion.
- [ ] Update `docs/specs/auth/tasks.md` checkboxes as implementation progresses.
