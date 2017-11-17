using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Miracl;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using RichardSzalay.MockHttp;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclClientTests
    {
        #region Consts
        private const string Endpoint = "https://api.dev.miracl.net";
        private const string TokenEndpoint = Endpoint + "/oidc/token";
        private const string UserEndpoint = Endpoint + "/oidc/userinfo";
        private const string AuthorizeEndpoint = Endpoint + "/authorize";
        private const string DvsVerifyEndpoint = Endpoint + Constants.DvsVerifyString;
        private const string DvsPubKeysEndpoint = Endpoint + Constants.DvsPublicKeyString;
        private const string CertUri = Endpoint + "/oidc/certs";
        private const string ValidClientId = "gnuei07bcyee8";
        private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJjaWQiOiJnbnVlaTA3YmN5ZWU4IiwiZXhwIjoxNDkzMDE2NDk5LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwic3ViIjoicGV0eWEua29sZXZhQG1pcmFjbC5jb20ifQ.MKPhkQ6-QbPIuD68cfy6QmuqelFUs1yUmW2dZn3ovjC8BkdCdgzRzysAvdTQCGe8F-WRTIAdmY00rXmC-z4_VVG1yESdOP2eCOD7zFmIXF9m5OTKMJJEaG6SOUoko5jypohmDk4MuLjOvfMOhXQfWKqLxkliMmM2e8J1FjSY7sF6Azg0Pq_mqK-mznIofbzR7tnA22XmlF_GRqYyoRpUEtkzU2ydoU9oGSJrwtwTeN1vXlzEwSvj65mVkuP4dIqJ5fmYstgTyKlzkwe8wFDHhB3Px-89lh5JRYKoY0nbDIUOc0RA0dKFnnFX3P0Cp9kp2QOwXYdRLmdhvhn7IeJjjw";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.CTQu9bx7vCV6pZvtDhEJTFjeasMJoZtbq93vFj2nwVODaGj5Ajp9ZYZvhD7eeYtOBzBH0rOAjNc_348bZXjiqi3IdpEMCTiQz0dPqxTlywUjwM0HCMQ0C0TIwUh4f8Os0rthF1a1yYy_WgL7FgFsmb12xwTwt_TXrKHqbHXV-eX8ip0GCQgao9B1VC3Jj4NEfEXuUSq2nexEx-p_H9LgqbNBro3i_kPoP7C3wfiSFS30qDDUKZLp3SeW90-ErcNQKmU7rukvujeCpeziYlycLyeRTPVmAOTMEyO4ABQyk4KTl_w9P2O8AXW6a2B7nfjGAQGVT_m9Z_56yzgJoJ9KRg";
        private const string Nonce = "80fcd53d3576621da623e1fdbe6c7c51416a975a3e53898ccb0bdeeb084be42f";
        private readonly Signature SignatureToVerify = new Signature("15760473979d2027bebca22d4e0ae40f49d0756dda507de71df99bf04d2a7d07",
                                                                      "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                                       "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                                       "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                                       "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b");
        #endregion

        #region Tests
        #region AuthorizationRequestUrl
        [Test]
        public void Test_AuthorizationRequestUrl()
        {
            var client = InitClient();
            var url = GetRequestUrl(client, Endpoint).Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("UserState").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        [Test]
        public void Test_AuthorizationRequestUrl_NullUri()
        {
            Assert.That(() => GetRequestUrl(new MiraclClient(), null),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_AuthorizationRequestUrl_InvalidUri()
        {
            Assert.That(() => GetRequestUrl(new MiraclClient(), "Not a URI"),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_AuthorizationRequestUrl_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetAuthorizationRequestUrlAsync(AuthorizeEndpoint),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("MiraclOptions should be set!"));
        }

        [Test]
        public void Test_AuthorizationRequestUrl_NoConfiguration()
        {
            var client = InitClient();
            client.Options.Configuration = new OpenIdConnectConfiguration();
            Assert.That(() => client.GetAuthorizationRequestUrlAsync(AuthorizeEndpoint),
                Throws.TypeOf<InvalidOperationException>().And.Property("Message").EqualTo("Cannot redirect to the authorization endpoint, the configuration may be missing or invalid."));
        }
        #endregion

        #region ValidateAuthorization
        [Test]
        public void Test_ValidateAuthorization_NullRequestQuery()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorization(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_SkipUnrecognizedRequests()
        {
            var client = InitClient();

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "MockCode");
            var query = new MockQuery(dictionary);

            client.Options.SkipUnrecognizedRequests = true;
            var res = client.ValidateAuthorization(query).Result;
            Assert.That(res, Is.Null);

            client.Options.SkipUnrecognizedRequests = false;
            Assert.That(() => client.ValidateAuthorization(query),
                Throws.TypeOf<ArgumentException>().And.Property("Message").StartWith("requestQuery does not have the proper"));

            dictionary.Add("state", "NotProtectedState");
            query = new MockQuery(dictionary);

            client.Options.SkipUnrecognizedRequests = true;
            res = client.ValidateAuthorization(query).Result;
            Assert.That(res, Is.Null);

            client.Options.SkipUnrecognizedRequests = false;
            Assert.That(() => client.ValidateAuthorization(query),
                Throws.TypeOf<ArgumentException>().And.Property("Message").StartWith("Invalid request properties"));
        }

        [Test]
        public void Test_ValidateAuthorization_EmptyReturnedState()
        {
            var client = InitClient();

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "MockCode");
            var query = new MockQuery(dictionary);
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey + "invalid", "MockState");
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));
            query = new MockQuery(dictionary);

            Assert.That(() => client.ValidateAuthorization(query),
                Throws.TypeOf<ArgumentException>().And.Property("Message").StartWith("requestQuery does not have the proper"));
        }

        [Test]
        public void Test_PopulateSessionProperties()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclClient client = InitClient(ValidClientId, null, mockHttp);

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add("code", "MockCode");

            client.UserState = "MockState";
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            dictionary.Add("session_state", "Session State");

            var query = new MockQuery(dictionary);

            client.Options.Configuration.CheckSessionIframe = "check";

            var properties = client.ValidateAuthorization(query).Result;
            Assert.That(properties, Is.Not.Null);
            Assert.AreEqual("MockToken", properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.AreEqual(properties.Items[OpenIdConnectSessionProperties.CheckSessionIFrame], "check");
            Assert.AreEqual(properties.Items[OpenIdConnectSessionProperties.SessionState], "Session State");
        }

        [Test]
        public void Test_ValidateAuthorization_NoOptions()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorization(new MockQuery(), "http://nothing/SigninMiracl"),
                Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("No Options found for authentication!"));
        }

        [Test]
        public void Test_ValidateAuthorization_MissingCode()
        {
            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.State, "state");
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorization(query),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_MissingState()
        {
            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "code");
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorization(query),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_InvalidState()
        {
            MiraclOptions options = new MiraclOptions();
            var dataProtectionProvider = new EphemeralDataProtectionProvider();
            var dataProtector = dataProtectionProvider.CreateProtector(typeof(MiraclClient).FullName, Constants.AuthenticationScheme, "v1");
            options.StateDataFormat = new PropertiesDataFormat(dataProtector);

            MiraclClient client = new MiraclClient(options);
            client.UserState = "DifferentState";

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "MockCode");

            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, "MockState");
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));
            var query = new MockQuery(dictionary);

            Assert.That(() => client.ValidateAuthorization(query, "http://nothing/SigninMiracl"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid state!"));
        }

        [Test]
        public void Test_ValidateAuthorization()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclClient client = InitClient(ValidClientId, null, mockHttp);

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add("code", "MockCode");

            client.UserState = "MockState";
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            var query = new MockQuery(dictionary);

            var response = client.ValidateAuthorization(query).Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
        }

        [Test]
        public void Test_ValidateAuthorization_Error()
        {
            var err = "some error";

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.State, "state");
            dictionary.Add(Constants.Error, err);
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorization(query),
                Throws.TypeOf<OpenIdConnectProtocolException>().And.Message.EqualTo("Error in the authorization response: " + err));
        }

        [Test]
        public void Test_ParseJwt_InvalidToken()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"InvalidIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            var client = InitClient(null, null, mockHttp);

            client.UserState = "74815e167fef4db7acda57d0cd486c83";// dictionary["state"];
            AuthenticationProperties properties = new AuthenticationProperties();
            var url = client.GetAuthorizationRequestUrlAsync(Endpoint, null, properties, client.UserState).Result;

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.State, client.State);
            dictionary.Add(Constants.Code, "MockCode");
            var query = new MockQuery(dictionary);

            Assert.That(() => client.ValidateAuthorization(query, "http://nothing/login"),
                 Throws.TypeOf<SecurityTokenException>().And.Message.StartsWith("Unable to read id token"));

            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "invalidUser@code.com"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Wrong token data!"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.invalidSignature" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(query, "http://nothing/login"),
                Throws.TypeOf<SecurityTokenInvalidSignatureException>());
        }
        #endregion

        #region ValidateAuthorizationCode
        [Test]
        public void Test_ValidateAuthorizationCode()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);

            var response = client.ValidateAuthorizationCode("MockCode", "wrong@mail.me").Result;
            Assert.That(response, Is.Null);

            response = client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));

            client.Nonce = "Invalid nonce";
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "empty@id.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token data!"));
        }

        [Test]
        public void Test_ValidateAuthorizationCode_UseTokenLifetime()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);
            client.Options.UseTokenLifetime = true;

            var response = client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.That(response.ExpiresUtc.HasValue);
        }

        [Test]
        public void Test_ValidateAuthorizationCode_UnsuccessfulRequest()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(UserEndpoint).Respond("text/html", "sth");
            mockHttp.When(TokenEndpoint).Respond(HttpStatusCode.BadRequest, "application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(null, null, mockHttp);

            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<OpenIdConnectProtocolException>().And.Property("Message").StartsWith("Message contains error: "));

        }

        [Test]
        public void Test_ValidateAuthorizationCode_InvalidTokenResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "invalid response");

            var client = InitClient(null, null, mockHttp);

            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<OpenIdConnectProtocolException>().And.Property("Message").StartsWith("Failed to parse token response body as JSON."));
        }

        [Test]
        public void Test_ValidateAuthorizationCode_NoOptions()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorizationCode(string.Empty, string.Empty),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("MiraclOptions should be set!"));
        }
        #endregion

        #region GetIdentity
        [Test]
        public void Test_GetIdentity_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetIdentity(Constants.AuthenticationScheme),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("MiraclOptions should be set!"));
        }

        [Test]
        public void Test_GetIdentity_WrongResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(UserEndpoint).Respond("text/html", "sth");
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);

            var response = client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);

            var result = client.GetIdentity(Constants.AuthenticationScheme).Result;
            Assert.That(result, Is.Null);
        }

        [Test]
        public void Test_GetIdentity_NoTokenEndpointUser()
        {
            var client = InitClient();

            Assert.That(() => client.GetIdentity(Constants.AuthenticationScheme),
             Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("ValidateAuthorization method should be called first!"));
        }
        #endregion

        #region other
        [Test]
        public void Test_ClearUserInfo()
        {
            MiraclClient client = new MiraclClient(new MiraclOptions());

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually            
            SetDiscovery(client);
            SetDvsConfiguration(client);

            var url = GetRequestUrl(client, "http://nothing").Result;
            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("UserState").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);

            client.ClearUserInfo(false);
            IsClientClear(client, false);

            client.ClearUserInfo(true);
            IsClientClear(client, true);
        }

        [Test]
        public void Test_Authorization()
        {
            MiraclClient client = InitClient(ValidClientId);

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add("code", "59Mu-PxYsj--mOId9etkOw");

            client.UserState = "MockState";
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            var query = new MockQuery(dictionary);

            var response = client.ValidateAuthorization(query, "http://nothing/login").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual(ValidAccessToken, response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.AreEqual(ValidIdToken, response.GetTokenValue(OpenIdConnectParameterNames.IdToken));
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("Bearer", response.GetTokenValue(OpenIdConnectParameterNames.TokenType));

            var identity = client.GetIdentity(Constants.AuthenticationScheme).Result.Identity as ClaimsIdentity;

            Assert.That(identity, Is.Not.Null);
            Assert.That(identity, Has.Property("IsAuthenticated").True);
            Assert.That(identity, Has.Property("Claims").Not.Null);

            Assert.That(client.UserJson, Is.Not.Null);
            Assert.That(client.Email, Is.Not.Null);
            Assert.That(client.UserId, Is.Not.Null);
            Assert.That(client.Email, Is.EqualTo("petya.koleva@miracl.com"));
            Assert.That(client.UserId, Is.EqualTo("petya.koleva@miracl.com"));

            Assert.That(identity.Claims.Any(c => c.Type.Equals("email")), Is.False);

            client.Options.GetClaimsFromUserInfoEndpoint = true;
            identity = client.GetIdentity(Constants.AuthenticationScheme).Result.Identity as ClaimsIdentity;
            var claim = identity.Claims.First(c => c.Type.Equals("email"));
            Assert.That(claim.Value, Is.EqualTo("petya.koleva@miracl.com"));
        }

        [Test]
        public void Test_TryGetValue()
        {
            var client = new MiraclClient();
            client.UserJson = JObject.Parse("{\"sub\":\"noone@miracl.com\"}");
            Assert.That(client.TryGetValue("sub"), Is.EqualTo("noone@miracl.com"));
        }

        [Test]
        public void Test_LoadOpenIdConnectConfigurationAsync()
        {
            MiraclOptions o = new MiraclOptions()
            {
                BackchannelHttpHandler = AddDiscoveryEndpoint(),
                Authority = Endpoint
            };
            var client = new MiraclClient(o);

            Assert.That(client.Options.Configuration, Is.Null);
            Assert.That(client.Options.DvsConfiguration, Is.Null);

            var url = client.GetAuthorizationRequestUrlAsync(Endpoint).Result;
            Assert.That(client.Options.Configuration, Is.Not.Null);
            Assert.That(client.Options.Configuration.AuthorizationEndpoint, Is.Not.Null);
            Assert.That(client.Options.Configuration.AuthorizationEndpoint, Is.EqualTo(AuthorizeEndpoint));
            Assert.That(client.Options.DvsConfiguration, Is.Not.Null);
            Assert.That(client.Options.DvsConfiguration.SigningKeys, Is.Not.Null);
            Assert.That(client.Options.DvsConfiguration.SigningKeys.Count, Is.Positive);
        }
        #endregion

        #region DVS
        [Test]
        public void Test_ParseSecurityKey()
        {
            var client = new MiraclClient(new MiraclOptions());
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentNullException>().And.Property("Message").Contains("Invalid dvs key!"));

            client.Options.DvsConfiguration = new OpenIdConnectConfiguration();
            JArray data = new JArray();
            data.Add(JObject.Parse("{\"wrong\":\"keys\"}"));
            client.Options.DvsConfiguration.AdditionalData.Add("keys", data);
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid RsaParameters"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            client.Options.DvsConfiguration.AdditionalData.Add("keys", null);
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentNullException>().And.Property("Message").Contains("Invalid dvs key"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            data.Add(JObject.Parse("{\"first\":\"tada\"}"));
            data.Add(JObject.Parse("{\"second\":\"tirira\"}"));
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentNullException>().And.Property("Message").Contains("Invalid dvs key"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            data.Clear();
            data.Add(JObject.Parse("{\"kty\":\"NoRSA\"}"));
            client.Options.DvsConfiguration.AdditionalData.Add("keys", data);
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid dvs key!"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            data.Clear();
            data.Add(JObject.Parse("{\"e\":\"AQAB\", \"n\":\"kwBfKdZTTt8dD-o1VPXKCH4hi28\", \"kid\":\"KeyId\"}"));
            client.Options.DvsConfiguration.AdditionalData.Add("keys", data);
            client.ParseSecurityKey();
            Assert.That(client.Options.DvsConfiguration.SigningKeys, Is.Not.Null);
            Assert.That(client.Options.DvsConfiguration.SigningKeys.Count, Is.Positive);
            Assert.That(client.Options.DvsConfiguration.SigningKeys.First().KeyId, Is.EqualTo("KeyId"));
        }

        [TestCase("", "s", "d", "d", "b")]
        [TestCase(null, "s", "d", "d", "b")]
        [TestCase("2", "", "d", "d", "b")]
        [TestCase("3", null, "d", "d", "b")]
        [TestCase("w", "s", "", "d", "b")]
        [TestCase("w", "s", null, "d", "b")]
        [TestCase("w", "s", "d", "", "b")]
        [TestCase("e", "s", "d", null, "b")]
        [TestCase("s", "s", "d", "d", "")]
        [TestCase("f", "s", "d", "d", null)]
        public void Test_Signature(string hash, string u, string v, string publicKey, string mpinId)
        {
            Signature s;
            Assert.That(() => s = new Signature(hash, mpinId, u, v, publicKey),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Value cannot be null"));
        }

        [Test]
        public void Test_DvsVerifySignature()
        {
            MiraclClient client = InitClient();

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsTrue(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.ValidSignature, resp.Status);
        }

        [Test]
        public void Test_DvsVerifySignature_InvalidSignature()
        {
            MiraclClient client = InitClient();

            Assert.That(() => client.DvsVerifySignature(null, 0),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Signature cannot be null"));
        }

        [Test]
        public void Test_DvsVerifySignature_InvalidTimestamp()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, -1),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Timestamp cannot has a negative value"));
        }

        [Test]
        public void Test_DvsVerifySignature_NullClientOptions()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<InvalidOperationException>().And.Message.Contains("No Options for verification - client credentials are used for the verification"));
        }

        [Test]
        public void Test_DvsVerifySignature_NullClientRsaPublicKey()
        {
            var client = new MiraclClient(new MiraclOptions());

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("DVS public key not found"));
        }

        [TestCase(HttpStatusCode.Unauthorized, VerificationStatus.BadPin)]
        [TestCase(HttpStatusCode.Gone, VerificationStatus.UserBlocked)]
        [TestCase(HttpStatusCode.Forbidden, VerificationStatus.MissingSignature)]
        public void Test_DvsVerifySignature_ServerResponseStatusNotOK(HttpStatusCode respStatusCode, VerificationStatus expected)
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond(respStatusCode, "application/json", string.Empty);

            var client = InitClient("MockClient", "MockSecret", mockHttp);

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsFalse(resp.IsSignatureValid);
            Assert.AreEqual(expected, resp.Status);
        }

        [Test]
        public void Test_DvsVerifySignature_ServerResponseStatusOK_InvalidResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"no-certificate\":\"ey.fQ.nD\"}");
            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("No `certificate` in the JSON response"));

            mockHttp.Clear();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"ey.fQ\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid DVS token format"));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyfQnD\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid DVS token format"));

            mockHttp.Clear();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "\"invalid\":\"json\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<Newtonsoft.Json.JsonReaderException>());
        }

        [Test]
        public void Test_DvsVerifySignature_ServerResponseStatusOK_RequestAndResponseHashesDiffer()
        {
            MiraclClient client = InitClient();

            Signature signature = new Signature("different-hash-value",
                                                "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b");

            Assert.That(() => client.DvsVerifySignature(signature, 0),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Signature hash and response hash do not match"));
        }

        [Test]
        public void Test_DvsVerifySignature_ServerResponseStatusOK_RequestTimestampAfterResponseTimestamp()
        {
            MiraclClient client = InitClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("The transaction is signed before the issue time"));
        }

        [TestCase("eyJjQXQiOjk5OTk5OTk5OTksImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ", "Invalid `cAt` value")]
        [TestCase("eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MX0", "No `hash` in the JWT payload")]
        [TestCase("eyJleHAiOjE0OTc0NDQ0NjEsImhhc2giOiIxNTc2MDQ3Mzk3OWQyMDI3YmViY2EyMmQ0ZTBhZTQwZjQ5ZDA3NTZkZGE1MDdkZTcxZGY5OWJmMDRkMmE3ZDA3In0", "No `cAt` in the signature")]
        public void Test_DvsVerifySignature_ServerResponseStatusOK_InvalidResponsePayload(string payload, string expected)
        {
            string respContent = string.Format("{{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.{0}.A19LAJpEZjFhwor0bj02AGh9\"}}", payload);

            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", respContent);

            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains(expected));
        }

        [Test]
        public void Test_DvsVerifySignature_ServerResponseStatusOK_PublicKeyNotMatching()
        {
            var client = InitClient();
            client.Options.DvsConfiguration.SigningKeys.Remove(client.Options.DvsConfiguration.SigningKeys.First());
            client.Options.DvsConfiguration.SigningKeys.Add(
                new RsaSecurityKey(
                    new System.Security.Cryptography.RSAParameters()
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                        Modulus = Base64UrlEncoder.DecodeBytes("kwBfKdZTTt8dD-o1VPXKCH4hi28-KUMsPy7OYBrk4lgCd1EHZCVvZdKkcjPW0kGjC3vuee7C5v516Siids684n_V8mznvLwNFGKJ3fdiubkxKc5cpgPrxH86uHr0sU")
                    }));

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsFalse(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.InvalidSignature, resp.Status);
        }

        [Test]
        public void Test_DvsCreateDocumentHash()
        {
            string document = "sample document";
            string expected = "1789c9eeee7dcbf9a5e9b47374e244f85263dc45922a249d37f7ba9fd4efb850";

            Assert.AreEqual(expected, new MiraclClient().DvsCreateDocumentHash(document));
        }
        #endregion
        #endregion

        #region Methods
        private static async Task<string> GetRequestUrl(MiraclClient client, string baseUri)
        {
            return await client.GetAuthorizationRequestUrlAsync(baseUri, client.Options == null ? new MiraclOptions { ClientId = "ClientID" } : client.Options);
        }

        private static void IsClientClear(MiraclClient client, bool isAuthorized)
        {
            if (isAuthorized)
            {
                Assert.That(client, Has.Property("UserState").Null);
                Assert.That(client, Has.Property("Nonce").Null);
                Assert.That(client, Has.Property("Options").Null);
            }
            else
            {
                Assert.That(client, Has.Property("UserState").Not.Null);
                Assert.That(client, Has.Property("Nonce").Not.Null);
                Assert.That(client, Has.Property("Options").Not.Null);
            }

            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
        }

        private MockHttpMessageHandler AddDiscoveryEndpoint()
        {
            var discoFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery.json");
            var document = File.ReadAllText(discoFileName);
            var jwksFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery_jwks.json");
            var jwks = File.ReadAllText(jwksFileName);

            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(Endpoint + Constants.DiscoveryPath).Respond("application/json", document);
            mockHttp.When(CertUri).Respond("application/json", jwks);
            mockHttp.When(DvsPubKeysEndpoint).Respond("application/json", "{\"keys\": [{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"s1\",\"n\":\"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k\",\"e\":\"AQAB\"}]}");

            return mockHttp;
        }

        private void SetDiscovery(MiraclClient client)
        {
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                Endpoint + Constants.DiscoveryPath,
                                    new OpenIdConnectConfigurationRetriever(),
                                new HttpClient(AddDiscoveryEndpoint())
                                );

            client.Options.Configuration = configManager.GetConfigurationAsync(CancellationToken.None).Result;

            Assert.That(client.Options.Configuration.AuthorizationEndpoint, Is.Not.Null);
            Assert.That(client.Options.Configuration.AuthorizationEndpoint, Is.EqualTo(AuthorizeEndpoint));
            Assert.That(client.Options.Configuration.JsonWebKeySet.Keys.Count, Is.EqualTo(1));
            Assert.That(client.Options.Configuration.JsonWebKeySet.Keys[0].Kty, Is.EqualTo("RSA"));
        }

        private void SetDvsConfiguration(MiraclClient client)
        {
            SetDvsManager(client);
            client.ParseSecurityKey();

            Assert.That(client.Options.DvsConfiguration.AdditionalData.Count, Is.EqualTo(1));
            Assert.That(client.Options.DvsConfiguration.AdditionalData.First().Key, Is.EqualTo("keys"));
            Assert.That(client.Options.DvsConfiguration.SigningKeys, Is.Not.Null);
            Assert.That(client.Options.DvsConfiguration.SigningKeys.Count, Is.Positive);
        }

        private static void SetDvsManager(MiraclClient client)
        {
            var _successHandler = new MockHttpMessageHandler();
            _successHandler.When(DvsPubKeysEndpoint).Respond("application/json", "{\"keys\": [{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"s1\",\"n\":\"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k\",\"e\":\"AQAB\"}]}");

            var dvsConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                DvsPubKeysEndpoint,
                                new OpenIdConnectConfigurationRetriever(),
                                new HttpClient(_successHandler)
            );

            client.Options.DvsConfiguration = dvsConfigManager.GetConfigurationAsync(CancellationToken.None).Result;
        }

        private MiraclClient InitClient(string clientId = "MockClient", string clientSecret = "MockSecret", MockHttpMessageHandler mockHttp = null)
        {
            if (mockHttp == null)
            {
                mockHttp = new MockHttpMessageHandler();
                mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"" + ValidAccessToken + "\",\"expires_in\":900,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
                mockHttp.When(UserEndpoint).Respond("application/json", "{\"email\":\"petya.koleva@miracl.com\",\"sub\":\"petya.koleva@miracl.com\"}");

                mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk\"}");
            }

            var options = new MiraclOptions();
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.BackchannelHttpHandler = mockHttp; 
            options.BackchannelTimeout = TimeSpan.FromMinutes(1);
            options.CallbackPath = new PathString("/login");
            options.Authority = Endpoint;

            options.SaveTokens = true;
            options.TokenValidationParameters.ValidateLifetime = false;
            options.ProtocolValidator.RequireTimeStampInNonce = false;

            var client = new MiraclClient(options);
            client.Nonce = Nonce;
            client.CallbackUrl = "/CallbackPath";

            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, client.Options);
            SetDiscovery(client);
            SetDvsConfiguration(client);

            return client;
        }
        #endregion
    }

    #region MockQuery
    class MockQuery : IQueryCollection
    {
        private Dictionary<string, StringValues> dict;

        public MockQuery()
        {
            dict = new Dictionary<string, StringValues>();
        }

        public MockQuery(Dictionary<string, StringValues> dictionary)
        {
            dict = new Dictionary<string, StringValues>(dictionary);
        }

        public StringValues this[string key] => dict[key];

        public int Count => dict.Count;

        public ICollection<string> Keys => dict.Keys;

        public bool ContainsKey(string key)
        {
            return dict.ContainsKey(key);
        }

        public IEnumerator<KeyValuePair<string, StringValues>> GetEnumerator()
        {
            return dict.GetEnumerator();
        }

        public bool TryGetValue(string key, out StringValues value)
        {
            return dict.TryGetValue(key, out value);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }
    }
    #endregion
}
