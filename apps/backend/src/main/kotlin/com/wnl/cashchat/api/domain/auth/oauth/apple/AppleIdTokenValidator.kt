package com.wnl.cashchat.api.domain.auth.oauth.apple

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import com.wnl.cashchat.api.domain.auth.exception.OAuthException
import com.wnl.cashchat.api.domain.auth.oauth.properties.OAuthProperties
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestClientResponseException
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Date

@Component
class AppleIdTokenValidator(
    private val oAuthProperties: OAuthProperties,
    private val restClient: RestClient,
    private val clock: Clock = Clock.systemUTC()
) {

    companion object {
        private const val APPLE_ISSUER = "https://appleid.apple.com"
        private val JWK_SET_CACHE_TTL: Duration = Duration.ofMinutes(5)
    }

    @Volatile
    private var cachedJwkSet: CachedJwkSet? = null

    fun validate(idToken: String): AppleIdTokenClaims {
        val signedJwt = parse(idToken)
        val rsaKey = selectKey(signedJwt.header.keyID)

        if (!signedJwt.verify(RSASSAVerifier(rsaKey))) {
            throw OAuthException("Invalid Apple id token signature")
        }

        val claims = signedJwt.jwtClaimsSet
        if (claims.issuer != APPLE_ISSUER) {
            throw OAuthException("Invalid Apple id token issuer")
        }

        val clientId = oAuthProperties.apple.clientId?.takeIf { it.isNotBlank() }
            ?: throw OAuthException("Missing Apple OAuth client id configuration")
        if (!claims.audience.contains(clientId)) {
            throw OAuthException("Invalid Apple id token audience")
        }

        if (claims.expirationTime == null || !claims.expirationTime.after(Date.from(clock.instant()))) {
            throw OAuthException("Expired Apple id token")
        }

        val subject = claims.subject?.takeIf { it.isNotBlank() }
            ?: throw OAuthException("Apple id token does not contain subject")

        return AppleIdTokenClaims(
            subject = subject,
            email = claims.getStringClaim("email"),
            emailVerified = claims.getClaim("email_verified")?.toString()?.toBooleanStrictOrNull()
        )
    }

    private fun parse(idToken: String): SignedJWT =
        try {
            SignedJWT.parse(idToken)
        } catch (e: Exception) {
            throw OAuthException("Invalid Apple id token", e)
        }

    private fun selectKey(keyId: String?): RSAKey {
        if (keyId.isNullOrBlank()) {
            throw OAuthException("Apple id token header does not contain key id")
        }

        val jwkSet = fetchJwkSet()
        val key = jwkSet.keys.firstOrNull { it.keyID == keyId }
            ?: throw OAuthException("No Apple public key found for token key id")

        return key as? RSAKey
            ?: throw OAuthException("Apple public key is not an RSA key")
    }

    private fun fetchJwkSet(): JWKSet {
        val now = clock.instant()
        cachedJwkSet?.takeIf { it.expiresAt.isAfter(now) }?.let { return it.jwkSet }

        return synchronized(this) {
            val refreshedNow = clock.instant()
            cachedJwkSet?.takeIf { it.expiresAt.isAfter(refreshedNow) }?.let { return@synchronized it.jwkSet }

            val jwkSet = fetchRemoteJwkSet()
            cachedJwkSet = CachedJwkSet(jwkSet, refreshedNow.plus(JWK_SET_CACHE_TTL))
            jwkSet
        }
    }

    private fun fetchRemoteJwkSet(): JWKSet {
        val jwksUri = oAuthProperties.apple.jwksUri

        return try {
            val rawJwks = restClient.get()
                .uri(jwksUri)
                .retrieve()
                .body(String::class.java)
                ?: throw OAuthException("Empty Apple JWKS response")

            JWKSet.parse(rawJwks)
        } catch (e: OAuthException) {
            throw e
        } catch (e: RestClientResponseException) {
            throw OAuthException("Apple JWKS fetch failed: ${e.statusCode}", e)
        } catch (e: RestClientException) {
            throw OAuthException("Apple JWKS fetch failed: network error", e)
        } catch (e: Exception) {
            throw OAuthException("Malformed Apple JWKS response", e)
        }
    }

    private data class CachedJwkSet(
        val jwkSet: JWKSet,
        val expiresAt: Instant,
    )
}

data class AppleIdTokenClaims(
    val subject: String,
    val email: String?,
    val emailVerified: Boolean?
)
