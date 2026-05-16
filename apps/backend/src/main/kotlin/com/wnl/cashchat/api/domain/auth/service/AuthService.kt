package com.wnl.cashchat.api.domain.auth.service

import com.wnl.cashchat.api.common.security.jwt.JwtTokenHandler
import com.wnl.cashchat.api.domain.auth.exception.AlreadyOAuthUserException
import com.wnl.cashchat.api.domain.auth.exception.InvalidTokenException
import com.wnl.cashchat.api.domain.auth.exception.OAuthException
import com.wnl.cashchat.api.domain.auth.oauth.apple.AppleIdTokenValidator
import com.wnl.cashchat.api.domain.auth.oauth.apple.AppleTokenClient
import com.wnl.cashchat.api.domain.auth.oauth.apple.AppleUserInfoExtractor
import com.wnl.cashchat.api.domain.auth.oauth.model.OAuthUserInfo
import com.wnl.cashchat.api.domain.auth.oauth.properties.OAuthProperties
import com.wnl.cashchat.api.domain.auth.oauth.util.OAuthUserInfoExtractor
import com.wnl.cashchat.api.domain.auth.persistence.entity.AuthProviderType
import com.wnl.cashchat.api.domain.auth.persistence.entity.RefreshToken
import com.wnl.cashchat.api.domain.auth.persistence.repository.RefreshTokenRepository
import com.wnl.cashchat.api.domain.auth.web.response.AuthResponse
import com.wnl.cashchat.api.domain.point.service.UserPointService
import com.wnl.cashchat.api.domain.user.persistence.entity.Role
import com.wnl.cashchat.api.domain.user.persistence.entity.User
import com.wnl.cashchat.api.domain.user.persistence.repository.UserRepository
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestClientResponseException
import java.time.LocalDateTime
import java.util.*


@Service
class AuthService(
    private val userRepository: UserRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val jwtTokenHandler: JwtTokenHandler,
    private val oAuthProperties: OAuthProperties,
    private val restClient: RestClient,
    private val userPointService: UserPointService,
    private val appleTokenClient: AppleTokenClient,
    private val appleIdTokenValidator: AppleIdTokenValidator,
    private val appleUserInfoExtractor: AppleUserInfoExtractor,
    oAuthUserInfoExtractors: List<OAuthUserInfoExtractor>
) {

    private val extractorMap = oAuthUserInfoExtractors.associateBy { it.providerType }

    @Transactional
    fun loginAsGuest(deviceToken: String): AuthResponse {

        val user = userRepository.findByDeviceToken(deviceToken)
            ?: userRepository.save(User(name = "Guest", deviceToken = deviceToken))

        if (user.provider != AuthProviderType.NONE) {
            throw AlreadyOAuthUserException("이미 OAuth로 가입된 사용자입니다. 소셜 로그인을 이용해주세요.")
        }

        userPointService.ensureInitialized(user)

        val accessToken = jwtTokenHandler.createAccessToken(user.id, user.role)

        return AuthResponse(
            accessToken = accessToken,
            refreshToken = null,
            userId = user.id,
            role = user.role
        )

    }

    @Transactional
    fun loginWithOAuth(
        registrationName: String,
        providerType: AuthProviderType,
        code: String,
        deviceToken: String?
    ): AuthResponse {

        val tokenResponse = exchangeAuthCodeForAccessToken(registrationName, code)

        val accessToken = tokenResponse["access_token"] as? String
            ?: throw OAuthException("OAuth token response does not contain 'access_token'")

        val rawUserInfo = fetchUserInfo(registrationName, accessToken)

        val extractor = extractorMap[providerType]
            ?: throw OAuthException("No OAuthUserInfoExtractor registered for provider: $providerType")

        val userInfo = extractor.extract(rawUserInfo)

        val user = lookupOrRegisterUser(userInfo, providerType, deviceToken)

        return buildAuthResponse(user)
    }

    @Transactional
    fun loginWithApple(
        authorizationCode: String,
        identityToken: String?,
        fullName: String?,
        deviceToken: String?
    ): AuthResponse {
        val tokenResponse = appleTokenClient.exchangeAuthorizationCode(authorizationCode)
        val idToken = tokenResponse.idToken?.takeIf { it.isNotBlank() }
            ?: throw OAuthException("Missing id_token in Apple response")
        val claims = appleIdTokenValidator.validate(idToken)
        val userInfo = appleUserInfoExtractor.extract(claims, fullName)
        val user = lookupOrRegisterUser(userInfo, AuthProviderType.APPLE, deviceToken)

        return buildAuthResponse(user)
    }

    // -- Exchange Auth Code For Access Token
    // -- & Fetch User Info From Open Authentication Provider

    @Suppress("UNCHECKED_CAST")
    private fun exchangeAuthCodeForAccessToken(registrationName: String, code: String): Map<String, Any> {

        val registration = oAuthProperties.getRegistration(registrationName)
        val provider = oAuthProperties.getProvider(registration.provider)

        val formData = LinkedMultiValueMap<String, String>().apply {
            add("code", code)
            add("client_id", registration.clientId)
            add("client_secret", registration.clientSecret)
            add("redirect_uri", registration.redirectUri)
            add("grant_type", "authorization_code")
        }

        return try {
            restClient.post()
                .uri(provider.tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .body(Map::class.java) as? Map<String, Any>
                ?: throw OAuthException("Empty or malformed token response from $registrationName (${provider.tokenUri})")
        } catch (e: RestClientResponseException) {
            throw OAuthException("Token exchange failed for $registrationName: ${e.statusCode}", e)
        } catch (e: RestClientException) {
            throw OAuthException("Token exchange failed for $registrationName: network error", e)
        }

    }

    @Suppress("UNCHECKED_CAST")
    private fun fetchUserInfo(registrationName: String, accessToken: String): Map<String, Any> {

        val registration = oAuthProperties.getRegistration(registrationName)
        val provider = oAuthProperties.getProvider(registration.provider)

        return try {
            restClient.get()
                .uri(provider.userInfoUri)
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .body(Map::class.java) as? Map<String, Any>
                ?: throw OAuthException("Empty or malformed user info response from $registrationName (${provider.userInfoUri})")
        } catch (e: RestClientResponseException) {
            throw OAuthException("User info fetch failed for $registrationName: ${e.statusCode}", e)
        } catch (e: RestClientException) {
            throw OAuthException("User info fetch failed for $registrationName: network error", e)
        }

    }

    // -- Look Up or Register User --

    private fun lookupOrRegisterUser(
        userInfo: OAuthUserInfo,
        providerType: AuthProviderType,
        deviceToken: String?
    ): User {

        val existingUser = userRepository.findByProviderAndProviderId(providerType, userInfo.providerId)
        if (existingUser != null) return existingUser

        val guestUser = deviceToken?.let { userRepository.findByDeviceToken(it) }

        if (guestUser != null && guestUser.provider == AuthProviderType.NONE) {
            return userRepository.save(guestUser.apply {
                email = userInfo.email
                name = userInfo.name
                profileImageUrl = userInfo.profileImageUrl
                provider = providerType
                providerId = userInfo.providerId
                role = Role.MEMBER
                this.deviceToken = null     // credential 분리: 승격 후 guest 로그인 경로 차단
            })
        }

        return userRepository.save(
            User(
                email = userInfo.email,
                name = userInfo.name,
                profileImageUrl = userInfo.profileImageUrl,
                provider = providerType,
                providerId = userInfo.providerId,
                role = Role.MEMBER
            )
        )
    }

    // -- Build Authorization Response --

    private fun buildAuthResponse(user: User): AuthResponse {

        userPointService.ensureInitialized(user)

        val accessToken = jwtTokenHandler.createAccessToken(user.id, user.role)
        val refreshToken = generateRefreshToken(user)

        return AuthResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            userId = user.id,
            role = user.role
        )

    }

    // -- Generate Refresh Token --

    private fun generateRefreshToken(user: User): String {

        val token = UUID.randomUUID().toString()

        refreshTokenRepository.save(
            RefreshToken(
                user = user,
                token = token,
                expiresAt = LocalDateTime.now().plusDays(14)
            )
        )

        return token
    }

    // -- Reissue Access Token Using Refresh Token --

    @Transactional
    fun reissueToken(refreshToken: String): AuthResponse {

        val storedToken = refreshTokenRepository.findByTokenForUpdate(refreshToken)
            ?: throw InvalidTokenException("Invalid refresh token")

        if (storedToken.expiresAt.isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(storedToken)
            throw InvalidTokenException("Refresh token expired")
        }

        val user = storedToken.user

        refreshTokenRepository.delete(storedToken)

        return buildAuthResponse(user)

    }

    @Transactional
    fun logout(userId: Long, refreshToken: String) {
        refreshTokenRepository.deleteByUserIdAndTokenReturningCount(userId, refreshToken)
    }
}
