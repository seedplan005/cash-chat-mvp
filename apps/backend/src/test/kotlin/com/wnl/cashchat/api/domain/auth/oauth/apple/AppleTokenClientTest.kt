package com.wnl.cashchat.api.domain.auth.oauth.apple

import com.wnl.cashchat.api.domain.auth.exception.OAuthException
import com.wnl.cashchat.api.domain.auth.oauth.properties.OAuthProperties
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.test.web.client.ExpectedCount.once
import org.springframework.test.web.client.match.MockRestRequestMatchers.content
import org.springframework.test.web.client.match.MockRestRequestMatchers.method
import org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo
import org.springframework.test.web.client.response.MockRestResponseCreators.withStatus
import org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess
import org.springframework.web.client.RestClient
import java.io.IOException

class AppleTokenClientTest : FunSpec({

    test("exchangeAuthorizationCode sends form request and maps Apple token response") {
        val fixture = tokenClientFixture()

        fixture.server.expect(once(), requestTo("https://appleid.apple.com/auth/token"))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().contentType(MediaType.APPLICATION_FORM_URLENCODED))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("client_id=com.nomadclub.cashchat")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("client_secret=client-secret")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("code=authorization-code")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("grant_type=authorization_code")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("redirect_uri=https%3A%2F%2Fapi.cashchat.example%2Fauth%2Fapple")))
            .andRespond(
                withSuccess(
                    """
                    {
                      "access_token": "apple-access-token",
                      "id_token": "apple-id-token",
                      "refresh_token": "apple-refresh-token",
                      "token_type": "Bearer",
                      "expires_in": 3600
                    }
                    """.trimIndent(),
                    MediaType.APPLICATION_JSON
                )
            )

        val response = fixture.client.exchangeAuthorizationCode("authorization-code")

        response.accessToken shouldBe "apple-access-token"
        response.idToken shouldBe "apple-id-token"
        response.refreshToken shouldBe "apple-refresh-token"
        response.tokenType shouldBe "Bearer"
        response.expiresIn shouldBe 3600
        fixture.server.verify()
    }

    test("exchangeAuthorizationCode converts Apple rejection to OAuthException") {
        val fixture = tokenClientFixture()
        fixture.server.expect(once(), requestTo("https://appleid.apple.com/auth/token"))
            .andRespond(withStatus(HttpStatus.BAD_REQUEST).body("""{"error":"invalid_grant"}"""))

        shouldThrow<OAuthException> {
            fixture.client.exchangeAuthorizationCode("bad-code")
        }.message shouldBe "Apple token exchange failed: 400 BAD_REQUEST"
        fixture.server.verify()
    }

    test("exchangeAuthorizationCode converts network failure to OAuthException") {
        val fixture = tokenClientFixture()
        fixture.server.expect(once(), requestTo("https://appleid.apple.com/auth/token"))
            .andRespond { throw IOException("network down") }

        shouldThrow<OAuthException> {
            fixture.client.exchangeAuthorizationCode("authorization-code")
        }.message shouldBe "Apple token exchange failed: network error"
        fixture.server.verify()
    }

    test("exchangeAuthorizationCode requires id token") {
        val fixture = tokenClientFixture()
        fixture.server.expect(once(), requestTo("https://appleid.apple.com/auth/token"))
            .andRespond(withSuccess("""{"access_token":"apple-access-token"}""", MediaType.APPLICATION_JSON))

        shouldThrow<OAuthException> {
            fixture.client.exchangeAuthorizationCode("authorization-code")
        }.message shouldBe "Apple token response does not contain 'id_token'"
        fixture.server.verify()
    }
})

private data class AppleTokenClientFixture(
    val client: AppleTokenClient,
    val server: MockRestServiceServer,
)

private fun tokenClientFixture(): AppleTokenClientFixture {
    val builder = RestClient.builder()
    val server = MockRestServiceServer.bindTo(builder).build()
    val secretGenerator = mock<AppleClientSecretGenerator>()
    whenever(secretGenerator.generate()).thenReturn("client-secret")

    return AppleTokenClientFixture(
        client = AppleTokenClient(
            oAuthProperties = OAuthProperties(
                apple = OAuthProperties.AppleProperties(
                    clientId = "com.nomadclub.cashchat",
                    teamId = "TEAM12345",
                    keyId = "KEY12345",
                    privateKey = "private-key",
                    tokenUri = "https://appleid.apple.com/auth/token",
                    jwksUri = "https://appleid.apple.com/auth/keys",
                    redirectUri = "https://api.cashchat.example/auth/apple",
                )
            ),
            restClient = builder.build(),
            clientSecretGenerator = secretGenerator,
        ),
        server = server,
    )
}
