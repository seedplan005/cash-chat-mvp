package com.wnl.cashchat.api.domain.auth.oauth.apple

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.wnl.cashchat.api.domain.auth.exception.OAuthException
import com.wnl.cashchat.api.domain.auth.oauth.properties.OAuthProperties
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.test.web.client.ExpectedCount.once
import org.springframework.test.web.client.match.MockRestRequestMatchers.method
import org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo
import org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess
import org.springframework.web.client.RestClient
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

class AppleIdTokenValidatorTest : FunSpec({

    val fixedClock = Clock.fixed(Instant.parse("2026-05-16T00:00:00Z"), ZoneOffset.UTC)

    test("validate accepts signed Apple id token and returns claims") {
        val key = rsaKey("kid-1")
        val fixture = validatorFixture(key, fixedClock)
        val token = appleToken(key)

        fixture.expectJwks()

        val claims = fixture.validator.validate(token)

        claims.subject shouldBe "apple-subject"
        claims.email shouldBe "user@example.com"
        claims.emailVerified shouldBe true
        fixture.server.verify()
    }

    test("validate reuses cached Apple JWKS") {
        val key = rsaKey("kid-1")
        val fixture = validatorFixture(key, fixedClock)
        val token = appleToken(key)

        fixture.expectJwks()

        fixture.validator.validate(token)
        fixture.validator.validate(token)

        fixture.server.verify()
    }

    test("validate rejects wrong audience") {
        val key = rsaKey("kid-1")
        val fixture = validatorFixture(key, fixedClock)
        val token = appleToken(key, audience = "other-client")
        fixture.expectJwks()

        shouldThrow<OAuthException> {
            fixture.validator.validate(token)
        }.message shouldBe "Invalid Apple id token audience"
        fixture.server.verify()
    }

    test("validate rejects expired token") {
        val key = rsaKey("kid-1")
        val fixture = validatorFixture(key, fixedClock)
        val token = appleToken(key, expiration = Instant.parse("2026-05-15T23:59:59Z"))
        fixture.expectJwks()

        shouldThrow<OAuthException> {
            fixture.validator.validate(token)
        }.message shouldBe "Expired Apple id token"
        fixture.server.verify()
    }

    test("validate rejects missing subject") {
        val key = rsaKey("kid-1")
        val fixture = validatorFixture(key, fixedClock)
        val token = appleToken(key, subject = null)
        fixture.expectJwks()

        shouldThrow<OAuthException> {
            fixture.validator.validate(token)
        }.message shouldBe "Apple id token does not contain subject"
        fixture.server.verify()
    }

    test("validate rejects unknown key id") {
        val signingKey = rsaKey("kid-1")
        val jwksKey = rsaKey("kid-2")
        val fixture = validatorFixture(jwksKey, fixedClock)
        val token = appleToken(signingKey)
        fixture.expectJwks()

        shouldThrow<OAuthException> {
            fixture.validator.validate(token)
        }.message shouldBe "No Apple public key found for token key id"
        fixture.server.verify()
    }
})

private data class AppleIdTokenValidatorFixture(
    val validator: AppleIdTokenValidator,
    val server: MockRestServiceServer,
    val jwksJson: String,
) {
    fun expectJwks() {
        server.expect(once(), requestTo("https://appleid.apple.com/auth/keys"))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess(jwksJson, MediaType.APPLICATION_JSON))
    }
}

private fun validatorFixture(key: RSAKey, clock: Clock): AppleIdTokenValidatorFixture {
    val builder = RestClient.builder()
    val server = MockRestServiceServer.bindTo(builder).build()
    val publicJwks = JWKSet(key.toPublicJWK()).toString()

    return AppleIdTokenValidatorFixture(
        validator = AppleIdTokenValidator(
            oAuthProperties = OAuthProperties(
                apple = OAuthProperties.AppleProperties(
                    clientId = "com.nomadclub.cashchat",
                    jwksUri = "https://appleid.apple.com/auth/keys",
                )
            ),
            restClient = builder.build(),
            clock = clock,
        ),
        server = server,
        jwksJson = publicJwks,
    )
}

private fun rsaKey(keyId: String): RSAKey =
    RSAKeyGenerator(2048)
        .keyID(keyId)
        .generate()

private fun appleToken(
    key: RSAKey,
    issuer: String = "https://appleid.apple.com",
    audience: String = "com.nomadclub.cashchat",
    expiration: Instant = Instant.parse("2026-05-16T00:05:00Z"),
    subject: String? = "apple-subject",
): String {
    val claims = JWTClaimsSet.Builder()
        .issuer(issuer)
        .audience(audience)
        .expirationTime(Date.from(expiration))
        .issueTime(Date.from(Instant.parse("2026-05-16T00:00:00Z")))
        .claim("email", "user@example.com")
        .claim("email_verified", "true")
        .apply { subject?.let { subject(it) } }
        .build()

    return SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(),
        claims
    ).apply {
        sign(RSASSASigner(key))
    }.serialize()
}
