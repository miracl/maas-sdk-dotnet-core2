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
        private const string RPInitiatedEndpoint = Endpoint + Constants.ActivateInitiateEndpoint;
        private const string CertUri = Endpoint + "/oidc/certs";
        private const string ValidClientId = "gnuei07bcyee8";
        private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJjaWQiOiJnbnVlaTA3YmN5ZWU4IiwiZXhwIjoxNDkzMDE2NDk5LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwic3ViIjoicGV0eWEua29sZXZhQG1pcmFjbC5jb20ifQ.MKPhkQ6-QbPIuD68cfy6QmuqelFUs1yUmW2dZn3ovjC8BkdCdgzRzysAvdTQCGe8F-WRTIAdmY00rXmC-z4_VVG1yESdOP2eCOD7zFmIXF9m5OTKMJJEaG6SOUoko5jypohmDk4MuLjOvfMOhXQfWKqLxkliMmM2e8J1FjSY7sF6Azg0Pq_mqK-mznIofbzR7tnA22XmlF_GRqYyoRpUEtkzU2ydoU9oGSJrwtwTeN1vXlzEwSvj65mVkuP4dIqJ5fmYstgTyKlzkwe8wFDHhB3Px-89lh5JRYKoY0nbDIUOc0RA0dKFnnFX3P0Cp9kp2QOwXYdRLmdhvhn7IeJjjw";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.CTQu9bx7vCV6pZvtDhEJTFjeasMJoZtbq93vFj2nwVODaGj5Ajp9ZYZvhD7eeYtOBzBH0rOAjNc_348bZXjiqi3IdpEMCTiQz0dPqxTlywUjwM0HCMQ0C0TIwUh4f8Os0rthF1a1yYy_WgL7FgFsmb12xwTwt_TXrKHqbHXV-eX8ip0GCQgao9B1VC3Jj4NEfEXuUSq2nexEx-p_H9LgqbNBro3i_kPoP7C3wfiSFS30qDDUKZLp3SeW90-ErcNQKmU7rukvujeCpeziYlycLyeRTPVmAOTMEyO4ABQyk4KTl_w9P2O8AXW6a2B7nfjGAQGVT_m9Z_56yzgJoJ9KRg";
        private const string Nonce = "80fcd53d3576621da623e1fdbe6c7c51416a975a3e53898ccb0bdeeb084be42f";
        private readonly Signature SignatureToVerify = new Signature("15760473979d2027bebca22d4e0ae40f49d0756dda507de71df99bf04d2a7d07",
                                                                      "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                                       "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                                       "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                                       "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b",
                                                                       "notnull");
        private const string NewUserToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhdWQiOiIzMTE3YmYwNC02NTFhLTQzYmEtYWQzMi0zY2I4NDVmZmZiM2YiLCJldmVudHMiOnsibmV3VXNlciI6eyJ1c2VySUQiOiJhc2RAZXhhbXBsZS5jb20iLCJkZXZpY2VOYW1lIjoiQ2hyb21lIG9uIFdpbmRvd3MiLCJoYXNoTVBpbklEIjoiNTkzMWVkNDM2M2NiYzczYzg4ZDZhMTczYmRlNzU1NDZhNzhmMmMxNmZiZTkwOTQ5YThlYmM0ZTFiMWRiNjM1ZiIsImFjdGl2YXRlS2V5IjoiMjliOWFlYTFkZDhiNDI1OTRiZDgyMDllM2Y0OTdkZmE4MzgxOGZkZjhjZGQwMjczMDJmODVkNmVlN2UyMTYwZiIsImV4cGlyZVRpbWUiOjE1MTI2NDA1MzZ9fSwiZXhwIjoxNTEyNjQwNTM2LCJpYXQiOjE1MTI2MzY5MzYsImlzcyI6Imh0dHBzOi8vYXBpLmRldi5taXJhY2wubmV0Iiwic3ViIjoiYXNkQGV4YW1wbGUuY29tIn0.XYj_LpQdJhnWOOoM-otm71HU21jQ_rQ7MFvwxWlDiNEriBTVBKFuiDs7wbt6Fzg0NnXAmMYSc9mFKVwn0jnJSpPB16N4X8yLOXDY8ugt7sUckrEAdYE9Vd1r-N-YvxU_S3fy2b5Jq2cpAjhlvgm28TApH5uV5YLWRjwiWyVaCo48VZmUafttH6CZLiTru2JUMw5tjrnaDaAOYGCsmXs-QtWPHm307riCH86TG_tuiQdp7HZWOQEUzuQ851WE914qs1xpn8lHYl8N8eMiX79BQTUiMZN5yCzS2FzIjYn1Q-hCe9iIqZY24SNogVQljb3ZUv1TCWtMP02G6KibaR9K9A";
        private const string ValidCustomerId = "3117bf04-651a-43ba-ad32-3cb845fffb3f";
        #endregion

        #region Tests
        #region GetAuthorizationRequestUrlAsync
        [Test]
        public void Test_GetAuthorizationRequestUrlAsync()
        {
            var client = InitClient();
            var url = GetRequestUrl(client, Endpoint).Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("UserState").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        [Test]
        public void Test_GetAuthorizationRequestUrlAsync_NullUri()
        {
            Assert.That(() => GetRequestUrl(new MiraclClient(), null),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_GetAuthorizationRequestUrlAsync_InvalidUri()
        {
            Assert.That(() => GetRequestUrl(new MiraclClient(), "Not a URI"),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_GetAuthorizationRequestUrlAsync_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetAuthorizationRequestUrlAsync(AuthorizeEndpoint),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("options").And.Message.Contains("MiraclOptions should be set!"));
        }

        [Test]
        public void Test_GetAuthorizationRequestUrlAsync_NoConfiguration()
        {
            var client = InitClient();
            client.Options.Configuration = new OpenIdConnectConfiguration();
            Assert.That(() => client.GetAuthorizationRequestUrlAsync(AuthorizeEndpoint),
                Throws.TypeOf<InvalidOperationException>().And.Property("Message").EqualTo("Cannot redirect to the authorization endpoint, the configuration may be missing or invalid."));
        }
        #endregion

        #region GetRPInitiatedAuthUriAsync
        [Test]
        public void Test_GetRPInitiatedAuthUriAsync()
        {
            var client = InitClient();
            var url = client.GetRPInitiatedAuthUriAsync("userId", string.Empty, Endpoint, client.Options).Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("UserState").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        [Test]
        public void Test_GetRPInitiatedAuthUriAsync_EmptyUserId()
        {
            var client = new MiraclClient();
            Assert.That(() => client.GetRPInitiatedAuthUriAsync("", "", ""),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("userId"));
        }

        [Test]
        public void Test_GetRPInitiatedAuthUriAsync_NoPlatformConnection()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"" + ValidAccessToken + "\",\"expires_in\":900,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"email\":\"petya.koleva@miracl.com\",\"sub\":\"petya.koleva@miracl.com\"}");

            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.GetRPInitiatedAuthUriAsync("userid", "", Endpoint),
                Throws.TypeOf<Exception>().And.Message.Contains("Connection problem with the Platform at "));
        }

        [Test]
        public void Test_GetRPInitiatedAuthUriAsync_InvalidPlatfromResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"" + ValidAccessToken + "\",\"expires_in\":900,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"email\":\"petya.koleva@miracl.com\",\"sub\":\"petya.koleva@miracl.com\"}");
            mockHttp.When(HttpMethod.Post, RPInitiatedEndpoint).Respond("application/json", "not a json structure");
            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.GetRPInitiatedAuthUriAsync("userid", "", Endpoint),
                Throws.TypeOf<Exception>().And.Message.Contains("Cannot generate an activation token from the server response."));
        }

        #endregion

        #region ValidateAuthorizationAsync
        [Test]
        public void Test_ValidateAuthorizationAsync_NullRequestQuery()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorizationAsync(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_SkipUnrecognizedRequests()
        {
            var client = InitClient();

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "MockCode");
            var query = new MockQuery(dictionary);

            client.Options.SkipUnrecognizedRequests = true;
            var res = client.ValidateAuthorizationAsync(query).Result;
            Assert.That(res, Is.Null);

            client.Options.SkipUnrecognizedRequests = false;
            Assert.That(() => client.ValidateAuthorizationAsync(query),
                Throws.TypeOf<ArgumentException>().And.Property("Message").StartWith("requestQuery does not have the proper"));

            dictionary.Add("state", "NotProtectedState");
            query = new MockQuery(dictionary);

            client.Options.SkipUnrecognizedRequests = true;
            res = client.ValidateAuthorizationAsync(query).Result;
            Assert.That(res, Is.Null);

            client.Options.SkipUnrecognizedRequests = false;
            Assert.That(() => client.ValidateAuthorizationAsync(query),
                Throws.TypeOf<ArgumentException>().And.Property("Message").StartWith("Invalid request properties"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_EmptyReturnedState()
        {
            var client = InitClient();

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "MockCode");
            var query = new MockQuery(dictionary);
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey + "invalid", "MockState");
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));
            query = new MockQuery(dictionary);

            Assert.That(() => client.ValidateAuthorizationAsync(query),
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
            client.AuthData.Add(client.UserState, client.Nonce);
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            dictionary.Add("session_state", "Session State");

            var query = new MockQuery(dictionary);

            client.Options.Configuration.CheckSessionIframe = "check";

            var properties = client.ValidateAuthorizationAsync(query).Result;
            Assert.That(properties, Is.Not.Null);
            Assert.AreEqual("MockToken", properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.AreEqual(properties.Items[OpenIdConnectSessionProperties.CheckSessionIFrame], "check");
            Assert.AreEqual(properties.Items[OpenIdConnectSessionProperties.SessionState], "Session State");
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_NoOptions()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorizationAsync(new MockQuery(), "http://nothing/SigninMiracl"),
                Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("No Options found for authentication!"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_MissingCode()
        {
            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.State, "state");
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorizationAsync(query),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_MissingState()
        {
            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.Code, "code");
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorizationAsync(query),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_InvalidState()
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

            Assert.That(() => client.ValidateAuthorizationAsync(query, "http://nothing/SigninMiracl"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid state!"));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclClient client = InitClient(ValidClientId, null, mockHttp);

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add("code", "MockCode");

            client.UserState = "MockState";
            client.AuthData.Add(client.UserState, client.Nonce);
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            var query = new MockQuery(dictionary);

            var response = client.ValidateAuthorizationAsync(query).Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
        }

        [Test]
        public void Test_ValidateAuthorizationAsync_Error()
        {
            var err = "some error";

            var dictionary = new Dictionary<string, StringValues>();
            dictionary.Add(Constants.State, "state");
            dictionary.Add(Constants.Error, err);
            var query = new MockQuery(dictionary);

            Assert.That(() => new MiraclClient(new MiraclOptions()).ValidateAuthorizationAsync(query),
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

            Assert.That(() => client.ValidateAuthorizationAsync(query, "http://nothing/login"),
                 Throws.TypeOf<SecurityTokenException>().And.Message.StartsWith("Unable to read token"));

            Assert.That(() => client.ValidateAuthorizationCodeAsync("MockCode", "invalidUser@code.com"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Wrong token data!"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.invalidSignature" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationAsync(query, "http://nothing/login"),
                Throws.TypeOf<SecurityTokenInvalidSignatureException>());
        }
        #endregion

        #region ValidateAuthorizationCodeAsync
        [Test]
        public void Test_ValidateAuthorizationCodeAsync()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);

            var response = client.ValidateAuthorizationCodeAsync("MockCode", "wrong@mail.me").Result;
            Assert.That(response, Is.Null);

            response = client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));

            client.Nonce = "Invalid nonce";
            Assert.That(() => client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce."));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCodeAsync("MockCode", "empty@id.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token data!"));
        }

        [Test]
        public void Test_ValidateAuthorizationCodeAsync_UseTokenLifetime()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);
            client.Options.UseTokenLifetime = true;

            var response = client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("MockToken", response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.That(response.ExpiresUtc.HasValue);
        }

        [Test]
        public void Test_ValidateAuthorizationCodeAsync_UnsuccessfulRequest()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(UserEndpoint).Respond("text/html", "sth");
            mockHttp.When(TokenEndpoint).Respond(HttpStatusCode.BadRequest, "application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(null, null, mockHttp);

            Assert.That(() => client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<OpenIdConnectProtocolException>().And.Property("Message").StartsWith("Message contains error: "));

        }

        [Test]
        public void Test_ValidateAuthorizationCodeAsync_InvalidTokenResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "invalid response");

            var client = InitClient(null, null, mockHttp);

            Assert.That(() => client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com"),
                Throws.TypeOf<OpenIdConnectProtocolException>().And.Property("Message").StartsWith("Failed to parse token response body as JSON."));
        }

        [Test]
        public void Test_ValidateAuthorizationCodeAsync_NoOptions()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorizationCodeAsync(string.Empty, string.Empty),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("Options").And.Message.Contains("MiraclOptions should be set!"));
        }
        #endregion

        #region GetIdentityAsync
        [Test]
        public void Test_GetIdentityAsync_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetIdentityAsync(Constants.AuthenticationScheme),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("Options").And.Message.Contains("MiraclOptions should be set!"));
        }

        [Test]
        public void Test_GetIdentityAsync_WrongResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(UserEndpoint).Respond("text/html", "sth");
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            var client = InitClient(ValidClientId, null, mockHttp);

            var response = client.ValidateAuthorizationCodeAsync("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);

            var result = client.GetIdentityAsync(Constants.AuthenticationScheme).Result;
            Assert.That(result, Is.Null);
        }

        [Test]
        public void Test_GetIdentityAsync_NoTokenEndpointUser()
        {
            var client = InitClient();

            Assert.That(() => client.GetIdentityAsync(Constants.AuthenticationScheme),
             Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("ValidateAuthorizationAsync method should be called first!"));
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
            client.AuthData.Add(client.UserState, client.Nonce);
            var authProp = new AuthenticationProperties();
            authProp.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, client.UserState);
            dictionary.Add("state", client.Options.StateDataFormat.Protect(authProp));

            var query = new MockQuery(dictionary);

            var response = client.ValidateAuthorizationAsync(query, "http://nothing/login").Result;
            Assert.That(response, Is.Not.Null);
            Assert.AreEqual(ValidAccessToken, response.GetTokenValue(OpenIdConnectParameterNames.AccessToken));
            Assert.AreEqual(ValidIdToken, response.GetTokenValue(OpenIdConnectParameterNames.IdToken));
            Assert.AreEqual("MockRefresh", response.GetTokenValue(OpenIdConnectParameterNames.RefreshToken));
            Assert.AreEqual("Bearer", response.GetTokenValue(OpenIdConnectParameterNames.TokenType));

            var identity = client.GetIdentityAsync(Constants.AuthenticationScheme).Result.Identity as ClaimsIdentity;

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
            identity = client.GetIdentityAsync(Constants.AuthenticationScheme).Result.Identity as ClaimsIdentity;
            var claim = identity.Claims.First(c => c.Type.Equals("email"));
            Assert.That(claim.Value, Is.EqualTo("petya.koleva@miracl.com"));
        }

        [Test]
        public void Test_TryGetUserInfoValue()
        {
            var client = new MiraclClient();
            client.UserJson = JObject.Parse("{\"sub\":\"noone@miracl.com\"}");
            Assert.That(client.TryGetUserInfoValue("sub"), Is.EqualTo("noone@miracl.com"));
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
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid dvs key!"));

            client.Options.DvsConfiguration = new OpenIdConnectConfiguration();
            JArray data = new JArray();
            data.Add(JObject.Parse("{\"wrong\":\"keys\"}"));
            client.Options.DvsConfiguration.AdditionalData.Add("keys", data);
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid RsaParameters"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            client.Options.DvsConfiguration.AdditionalData.Add("keys", null);
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid dvs key"));

            client.Options.DvsConfiguration.AdditionalData.Clear();
            data.Add(JObject.Parse("{\"first\":\"tada\"}"));
            data.Add(JObject.Parse("{\"second\":\"tirira\"}"));
            Assert.That(() => client.ParseSecurityKey(),
                Throws.TypeOf<ArgumentException>().And.Property("Message").Contains("Invalid dvs key"));

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

        [TestCase("", "s", "d", "d", "b", null)]
        [TestCase(null, "s", "d", "d", "b", "")]
        [TestCase("2", "", "d", "d", "b", "1")]
        [TestCase("3", null, "d", "d", "b", "d")]
        [TestCase("w", "s", "", "d", "b", "g")]
        [TestCase("w", "s", null, "d", "b", "g")]
        [TestCase("w", "s", "d", "", "b", "g")]
        [TestCase("e", "s", "d", null, "b", "g")]
        [TestCase("s", "s", "d", "d", "", "d")]
        [TestCase("f", "s", "d", "d", null, "2")]
        [TestCase("f", "s", "d", "d", "d", null)]
        public void Test_Signature(string hash, string u, string v, string publicKey, string mpinId, string dtas)
        {
            Signature s;
            Assert.That(() => s = new Signature(hash, mpinId, u, v, publicKey, dtas),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Value cannot be null"));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync()
        {
            MiraclClient client = InitClient();

            var resp = client.DvsVerifySignatureAsync(SignatureToVerify, 0).Result;

            Assert.IsTrue(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.ValidSignature, resp.Status);
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_InvalidSignature()
        {
            MiraclClient client = InitClient();

            Assert.That(() => client.DvsVerifySignatureAsync(null, 0),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Signature cannot be null"));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_InvalidTimestamp()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, -1),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Timestamp cannot has a negative value"));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_NullClientOptions()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
               Throws.TypeOf<InvalidOperationException>().And.Message.Contains("No Options for verification - client credentials are used for the verification"));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_NullClientRsaPublicKey()
        {
            var client = new MiraclClient(new MiraclOptions());

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("DVS public key not found"));
        }

        [TestCase(HttpStatusCode.Unauthorized, VerificationStatus.BadPin)]
        [TestCase(HttpStatusCode.Gone, VerificationStatus.UserBlocked)]
        [TestCase(HttpStatusCode.Forbidden, VerificationStatus.MissingSignature)]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusNotOK(HttpStatusCode respStatusCode, VerificationStatus expected)
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond(respStatusCode, "application/json", string.Empty);

            var client = InitClient("MockClient", "MockSecret", mockHttp);

            var resp = client.DvsVerifySignatureAsync(SignatureToVerify, 0).Result;

            Assert.IsFalse(resp.IsSignatureValid);
            Assert.AreEqual(expected, resp.Status);
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusOK_InvalidResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"no-certificate\":\"ey.fQ.nD\"}");
            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("No `certificate` in the JSON response."));

            mockHttp.Clear();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"ey.fQ\"}");
            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid DVS token format."));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyfQnD\"}");
            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
               Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid DVS token format."));

            mockHttp.Clear();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", "\"invalid\":\"json\"}");
            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, 0),
               Throws.TypeOf<Newtonsoft.Json.JsonReaderException>());
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusOK_RequestAndResponseHashesDiffer()
        {
            MiraclClient client = InitClient();

            Signature signature = new Signature("different-hash-value",
                                                "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b",
                                                "WyIwZmE0NzBhNDA4Yjg3Y2M3MWU5MzdmNDQxYjAxOTg5NTU3OTQxZWMwZGIzOTE2MWRjN2JiMDg2MGJkZjk5MTEzIiwiOTRmNDkzYmViYmZmMWM0ZmU0ZDg3NmE2YTdiZjM1NzRkMjg5YmIzMzRmYjViYTczMWM0MDliYTI2ZThiNjNmNyJd");

            Assert.That(() => client.DvsVerifySignatureAsync(signature, 0),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Signature hash and response hash do not match"));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusOK_RequestTimestampAfterResponseTimestamp()
        {
            MiraclClient client = InitClient();

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("The transaction is signed before the issue time"));
        }

        [TestCase("eyJjQXQiOjk5OTk5OTk5OTksImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ", "Invalid `cAt` value")]
        [TestCase("eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MX0", "No `hash` in the JWT payload")]
        [TestCase("eyJleHAiOjE0OTc0NDQ0NjEsImhhc2giOiIxNTc2MDQ3Mzk3OWQyMDI3YmViY2EyMmQ0ZTBhZTQwZjQ5ZDA3NTZkZGE1MDdkZTcxZGY5OWJmMDRkMmE3ZDA3In0", "No `cAt` in the signature")]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusOK_InvalidResponsePayload(string payload, string expected)
        {
            string respContent = string.Format("{{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.{0}.A19LAJpEZjFhwor0bj02AGh9\"}}", payload);

            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DvsVerifyEndpoint).Respond("application/json", respContent);

            var client = InitClient("MockClient", "MockSecret", mockHttp);

            Assert.That(() => client.DvsVerifySignatureAsync(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains(expected));
        }

        [Test]
        public void Test_DvsVerifySignatureAsync_ServerResponseStatusOK_PublicKeyNotMatching()
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

            var resp = client.DvsVerifySignatureAsync(SignatureToVerify, 0).Result;

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

        [Test]
        public void Test_DvsCreateAuthToken()
        {
            string docHash = "1789c9eeee7dcbf9a5e9b47374e244f85263dc45922a249d37f7ba9fd4efb850";
            string clientId = "MockClientId";
            string clientSecret = "MockClientSecret";

            MiraclOptions options = new MiraclOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            };

            MiraclClient client = new MiraclClient(options);
            string expected = "TW9ja0NsaWVudElkOmU1M2U4ZTY2NGM0NWJlMzQyZWZjZmExNDZlNTM4ODc3ZGYyYWQ2NDViNGExYTA1OWIxNmY5NTBkMzhhZGUzYzU=";

            Assert.AreEqual(expected, client.DvsCreateAuthToken(docHash));
        }

        [Test]
        public void Test_DvsCreateAuthToken_NullDocHash()
        {
            MiraclClient client = new MiraclClient();

            Assert.That(() => client.DvsCreateAuthToken(null),
              Throws.TypeOf<ArgumentNullException>().And.Message.Contains("The hash of the document cannot be null."));
        }

        [Test]
        public void Test_DvsCreateAuthToken_NullClientOptions()
        {
            MiraclClient client = new MiraclClient();

            Assert.That(() => client.DvsCreateAuthToken("docHash"),
              Throws.TypeOf<InvalidOperationException>().And.Message.Contains("Options cannot be null - client credentials are used for token creation."));
        }

        [Test]
        public void Test_DvsCreateAuthToken_NullClientSecret()
        {
            string clientId = "MockClientId";
            string clientSecret = null;

            MiraclOptions options = new MiraclOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            };

            MiraclClient client = new MiraclClient(options);

            Assert.That(() => client.DvsCreateAuthToken("dockHash"),
              Throws.TypeOf<InvalidOperationException>().And.Message.Contains("Options.ClientSecret cannot be null."));
        }
        #endregion

        #region PV
        [TestCase(null, null, null, null, 0)]
        [TestCase("", "", "", "", 0)]
        public void Test_Identity_IsEmpty(string id, string deviceName, string mPinIdHash, string activateKey, Int64 activateExpireTime)
        {
            var identity = new Miracl.Identity(id, deviceName, mPinIdHash, activateKey, activateExpireTime);

            Assert.IsTrue(identity.IsEmpty());
        }

        [Test]
        public void Test_Identity_IsExpired()
        {
            var expiredIdentity = new Miracl.Identity("", "", "", "", 0);

            Assert.IsTrue(expiredIdentity.IsExpired());

            var expTime = (Int64)((DateTime.UtcNow.AddDays(1) - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
            var notExpiredIdentity = new Miracl.Identity("", "", "", "", expTime);

            Assert.IsFalse(notExpiredIdentity.IsExpired());
        }

        [Test]
        public void Test_Identity_Constructor()
        {
            var identity = new Miracl.Identity(new IdentityInfo("asd@example.com", "deviceNameValue"), new IdentityActivationParams("hash", "key"), 1);

            Assert.That(identity.Info.Id, Is.EqualTo("asd@example.com"));
            Assert.That(identity.Info.DeviceName, Is.EqualTo("deviceNameValue"));
            Assert.That(identity.ActivationParams, Is.Not.Null);
            Assert.That(identity.ActivationParams.MPinIdHash, Is.EqualTo("hash"));
            Assert.That(identity.ActivationParams.ActivateKey, Is.EqualTo("key"));
            Assert.That(identity.ActivateExpireTime, Is.EqualTo(1));
        }

        [TestCase("{\"newUser\":{}}")]
        [TestCase("{\"newUser\":{\"deviceName\":\"Chrome on Windows\",\"hashMPinID\":\"5931ed4363cbc73c88d6a173bde75546a78f2c16fbe90949a8ebc4e1b1db635f\",\"activateKey\":\"29b9aea1dd8b42594bd8209e3f497dfa83818fdf8cdd027302f85d6ee7e2160f\",\"expireTime\":1512640536}}")]
        [TestCase("{\"newUser\":{\"userID\":\"asd@example.com\",\"hashMPinID\":\"5931ed4363cbc73c88d6a173bde75546a78f2c16fbe90949a8ebc4e1b1db635f\",\"activateKey\":\"29b9aea1dd8b42594bd8209e3f497dfa83818fdf8cdd027302f85d6ee7e2160f\",\"expireTime\":1512640536}}")]
        [TestCase("{\"newUser\":{\"userID\":\"asd@example.com\",\"deviceName\":\"Chrome on Windows\",\"activateKey\":\"29b9aea1dd8b42594bd8209e3f497dfa83818fdf8cdd027302f85d6ee7e2160f\",\"expireTime\":1512640536}}")]
        [TestCase("{\"newUser\":{\"userID\":\"asd@example.com\",\"deviceName\":\"Chrome on Windows\",\"hashMPinID\":\"5931ed4363cbc73c88d6a173bde75546a78f2c16fbe90949a8ebc4e1b1db635f\",\"expireTime\":1512640536}}")]
        [TestCase("{\"newUser\":{\"userID\":\"asd@example.com\",\"deviceName\":\"Chrome on Windows\",\"hashMPinID\":\"5931ed4363cbc73c88d6a173bde75546a78f2c16fbe90949a8ebc4e1b1db635f\",\"activateKey\":\"29b9aea1dd8b42594bd8209e3f497dfa83818fdf8cdd027302f85d6ee7e2160f\"}}")]
        [TestCase("{\"newUser\":{\"userID\":\"asd@example.com\",\"deviceName\":\"Chrome on Windows\",\"hashMPinID\":\"5931ed4363cbc73c88d6a173bde75546a78f2c16fbe90949a8ebc4e1b1db635f\",\"activateKey\":\"29b9aea1dd8b42594bd8209e3f497dfa83818fdf8cdd027302f85d6ee7e2160f\",\"expireTime\":\"invalid time\"}}")]
        public void Test_CreateIdentity_InvalidUserData(string data)
        {
            var userData = new Claim("events", data);

            Assert.That(() => new MiraclClient().CreateIdentity(userData),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid data for creating a new identity."));
        }

        [TestCase("")]
        [TestCase(null)]
        public void Test_TryGetTokenDataByName_EmptyOrNullPropertyName(string propertyName)
        {
            var userData = new Claim("events", "{\"newUser\":{\"userID\":\"asd@example.com\"}}");
            var data = JObject.Parse(userData.Value).GetValue("newUser");

            Assert.That(new MiraclClient().TryGetTokenDataByName(data, propertyName), Is.EqualTo(string.Empty));
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

        private ConfigurationManager<OpenIdConnectConfiguration> GetConfigManager(MiraclClient client)
        {
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                               Endpoint + Constants.DiscoveryPath,
                                   new OpenIdConnectConfigurationRetriever(),
                               new HttpClient(AddDiscoveryEndpoint())
                               );
        }

        private void SetDiscovery(MiraclClient client)
        {
            var configManager = GetConfigManager(client);
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

                mockHttp.When(HttpMethod.Post, RPInitiatedEndpoint).Respond("application/json", "{\"mpinId\":\"7b22696174223a313534313636323732352c22757365724944223a2270657479612e6b6f6c657661406d697261636c2e636f6d222c22634944223a2263313431623638342d643130342d346236312d626466392d663530316265303734333836222c2273616c74223a2275733739437647584f5254444f7272355441544b3677222c2276223a352c2273636f7065223a5b2261757468225d2c22647461223a5b5d2c227674223a227076227d\",\"hashMPinId\":\"7167bc0f576dd6db3afb868370c941d41388f68a86426e377fe16a747532fddd\",\"actToken\":\"5ab9551721a45d778ac77d3da1ca1317\",\"expireTime\":1541662815}");
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
