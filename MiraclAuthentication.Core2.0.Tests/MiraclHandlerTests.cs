using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Miracl;
using NUnit.Framework;
using RichardSzalay.MockHttp;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclHandlerTests
    {
        private static readonly string ChallengeEndpoint = TestServerBuilder.TestHost + TestServerBuilder.Challenge;

        private static readonly string TokenEndpoint = TestServerBuilder.DefaultAuthority + "/oidc/token";
        private static readonly string UserEndpoint = TestServerBuilder.DefaultAuthority + "/oidc/userinfo";
        private static readonly string AuthorizeEndpoint = TestServerBuilder.DefaultAuthority + "/authorize";
        private static readonly string DvsVerifyEndpoint = TestServerBuilder.DefaultAuthority + Constants.DvsVerifyString;
        private static readonly string DvsPubKeysEndpoint = TestServerBuilder.DefaultAuthority + Constants.DvsPublicKeyString;
        private static readonly string CertUri = TestServerBuilder.DefaultAuthority + "/oidc/certs";

        private const string ValidClientId = "gnuei07bcyee8";
        private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJjaWQiOiJnbnVlaTA3YmN5ZWU4IiwiZXhwIjoxNDkzMDE2NDk5LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwic3ViIjoicGV0eWEua29sZXZhQG1pcmFjbC5jb20ifQ.MKPhkQ6-QbPIuD68cfy6QmuqelFUs1yUmW2dZn3ovjC8BkdCdgzRzysAvdTQCGe8F-WRTIAdmY00rXmC-z4_VVG1yESdOP2eCOD7zFmIXF9m5OTKMJJEaG6SOUoko5jypohmDk4MuLjOvfMOhXQfWKqLxkliMmM2e8J1FjSY7sF6Azg0Pq_mqK-mznIofbzR7tnA22XmlF_GRqYyoRpUEtkzU2ydoU9oGSJrwtwTeN1vXlzEwSvj65mVkuP4dIqJ5fmYstgTyKlzkwe8wFDHhB3Px-89lh5JRYKoY0nbDIUOc0RA0dKFnnFX3P0Cp9kp2QOwXYdRLmdhvhn7IeJjjw";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.CTQu9bx7vCV6pZvtDhEJTFjeasMJoZtbq93vFj2nwVODaGj5Ajp9ZYZvhD7eeYtOBzBH0rOAjNc_348bZXjiqi3IdpEMCTiQz0dPqxTlywUjwM0HCMQ0C0TIwUh4f8Os0rthF1a1yYy_WgL7FgFsmb12xwTwt_TXrKHqbHXV-eX8ip0GCQgao9B1VC3Jj4NEfEXuUSq2nexEx-p_H9LgqbNBro3i_kPoP7C3wfiSFS30qDDUKZLp3SeW90-ErcNQKmU7rukvujeCpeziYlycLyeRTPVmAOTMEyO4ABQyk4KTl_w9P2O8AXW6a2B7nfjGAQGVT_m9Z_56yzgJoJ9KRg";
        private const string Nonce = "80fcd53d3576621da623e1fdbe6c7c51416a975a3e53898ccb0bdeeb084be42f";


        [Test]
        public void Test_HandleChallengeAsync_ChallengeIsIssuedCorrectly()
        {
            var settings = new TestSettings(
                opt =>
                {
                    opt.Authority = TestServerBuilder.DefaultAuthority;
                    opt.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
                    opt.ClientId = "Test Id";
                    opt.ResponseType = "code";
                    opt.BackchannelHttpHandler = GetMockHttpHandler();
                    opt.ProtocolValidator.RequireNonce = true;
                });

            var server = settings.CreateTestServer();
            var transaction = server.SendAsync(ChallengeEndpoint).Result;

            var res = transaction.Response;
            Assert.AreEqual(HttpStatusCode.Redirect, res.StatusCode);
            Assert.NotNull(res.Headers.Location);

            settings.ValidateChallengeRedirect(
                res.Headers.Location,
                OpenIdConnectParameterNames.ClientId,
                OpenIdConnectParameterNames.ResponseType,
                OpenIdConnectParameterNames.Scope,
                OpenIdConnectParameterNames.RedirectUri,
                OpenIdConnectParameterNames.SkuTelemetry,
                OpenIdConnectParameterNames.VersionTelemetry);
        }

        [Test]
        public void Test_HandleChallengeAsync_AuthorizationRequestDoesNotIncludeTelemetryParametersWhenDisabled()
        {
            var setting = new TestSettings(opt =>
            {
                opt.ClientId = "Test Id";
                opt.Authority = TestServerBuilder.DefaultAuthority;
                opt.DisableTelemetry = true;
                opt.BackchannelHttpHandler = GetMockHttpHandler();
            });

            var server = setting.CreateTestServer();
            var transaction = server.SendAsync(ChallengeEndpoint).Result;

            var res = transaction.Response;
            Assert.AreEqual(HttpStatusCode.Redirect, res.StatusCode);
            Assert.That(res.Headers.Location.Query, Does.Not.Contain(OpenIdConnectParameterNames.SkuTelemetry));
            Assert.That(res.Headers.Location.Query, Does.Not.Contain(OpenIdConnectParameterNames.VersionTelemetry));
        }

        [Test]
        public void Test_HandleChallengeAsync_SetsNonceAndStateCookies()
        {
            var settings = new TestSettings(opt =>
            {
                opt.ClientId = "Test Id";
                opt.Authority = TestServerBuilder.DefaultAuthority;
                opt.BackchannelHttpHandler = GetMockHttpHandler();
            });
            var server = settings.CreateTestServer();
            var transaction = server.SendAsync(ChallengeEndpoint).Result;

            var firstCookie = transaction.SetCookie.First();
            StringAssert.StartsWith(".AspNetCore.Correlation.MIRACL.", firstCookie);
            StringAssert.Contains("expires", firstCookie);

            var secondCookie = transaction.SetCookie.Skip(1).First();
            StringAssert.Contains(OpenIdConnectDefaults.CookieNoncePrefix, secondCookie);
            StringAssert.Contains("expires", secondCookie);
        }

        [Test]
        public void Test_HandleChallengeAsync_Challenge_WithEmptyConfig_Fails()
        {
            var settings = new TestSettings(
                opt =>
                {
                    opt.ClientId = "Test Id With Empty Config";
                    opt.Configuration = new OpenIdConnectConfiguration();
                    opt.Authority = TestServerBuilder.DefaultAuthority;
                    opt.BackchannelHttpHandler = GetMockHttpHandler();
                });

            var server = settings.CreateTestServer();
            Assert.That(() => server.SendAsync(ChallengeEndpoint),
                Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("Cannot redirect to the authorization endpoint, the configuration may be missing or invalid."));
        }

        private MockHttpMessageHandler GetMockHttpHandler()
        {
            var discoFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery.json");
            var document = File.ReadAllText(discoFileName);
            var jwksFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery_jwks.json");
            var jwks = File.ReadAllText(jwksFileName);

            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TestServerBuilder.DefaultAuthority + Constants.DiscoveryPath).Respond("application/json", document);
            mockHttp.When(CertUri).Respond("application/json", jwks);
            mockHttp.When(DvsPubKeysEndpoint).Respond("application/json", "{\"keys\": [{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"s1\",\"n\":\"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k\",\"e\":\"AQAB\"}]}");

            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"" + ValidAccessToken + "\",\"expires_in\":900,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"email\":\"petya.koleva@miracl.com\",\"sub\":\"petya.koleva@miracl.com\"}");

            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk\"}");

            return mockHttp;
        }
    }
}
