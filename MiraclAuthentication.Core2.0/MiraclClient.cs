using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Miracl
{
    /// <summary>
    /// Relying Party client class for connecting to the MIRACL server.
    /// </summary>
    public class MiraclClient
    {
        #region Fields
        internal JObject UserJson;
        internal string CallbackUrl;
        internal string State;

        private OpenIdConnectMessage TokenEndpointResponse;
        private JwtSecurityToken IdTokenEndpointJwt;
        private ClaimsPrincipal TokenEndpointUser;        
        #endregion

        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        public MiraclClient()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        /// <param name="options">The options which describes the authenticating parameters.</param>
        public MiraclClient(MiraclOptions options) : this()
        {
            this.Options = options;
        }
        #endregion

        #region Members
        /// <summary>
        /// Specifies the MIRACL client objects for authentication.
        /// </summary>
        /// <value>
        /// The options values.
        /// </value>
        public MiraclOptions Options
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the user identifier name when authenticated.
        /// </summary>
        /// <value>
        /// The user identifier name.
        /// </value>
        public string UserId
        {
            get
            {
                return TryGetValue("sub");
            }
        }

        /// <summary>
        /// Gets the email of the authentication.
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        public string Email
        {
            get
            {
                return TryGetValue("email");
            }
        }

        /// <summary>
        /// A randomly generated unique value included in the request that is returned in the token response used for preventing cross-site request forgery attacks. 
        /// </summary>
        /// </value>
        /// The State value.
        public string UserState
        {
            get;
            internal set;
        }

        /// <summary>
        /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        /// </summary>
        /// <value>
        /// The Nonce value.
        /// </value>
        public string Nonce
        {
            get;
            internal set;
        }

        #endregion

        #region Methods
        #region Public
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system. After URL
        /// redirects back, pass the query string to ValidateAuthorization method to complete
        /// the authorization with server.
        /// </summary>
        /// <param name="baseUri">The base URI of the calling app.</param>
        /// <param name="options">(Optional) The options for authentication.</param>
        /// <param name="properties">(Optional) The authentication session properties.</param>
        /// <param name="userStateString">(Optional) Specify a new Open ID Connect user state. If not set, new GUID is generated instead.</param>
        /// <returns>
        /// The callback url.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="baseUri" /> is not a valid Uri.
        /// or
        /// Invalid dvs key!
        /// </exception>
        /// <exception cref="ArgumentNullException">MiraclOptions should be set!</exception>
        /// <exception cref="InvalidOperationException">Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.</exception>
        public async Task<string> GetAuthorizationRequestUrlAsync(string baseUri, MiraclOptions options = null, AuthenticationProperties properties = null, string userStateString = null)
        {
            if (!Uri.IsWellFormedUriString(baseUri, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("The baseUri is not well formed", "baseUri");
            }

            this.Options = options ?? this.Options;
            if (this.Options == null)
            {
                throw new ArgumentNullException("MiraclOptions should be set!");
            }

            await LoadOpenIdConnectConfigurationAsync();

            if (this.Options.Configuration == null || string.IsNullOrEmpty(this.Options.Configuration.AuthorizationEndpoint))
            {
                throw new InvalidOperationException(
                    "Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.");
            }

            return GetAuthorizationRequestUrl(baseUri, properties, userStateString);
        }

        /// <summary>
        /// Returns the authentication properties of the response if the validation succeeds or null
        /// if the request requires it on error.
        /// </summary>
        /// <param name="requestQuery">The query string returned from authorization URL.</param>
        /// <param name="redirectUri">The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <returns>
        /// The response's properties used in the authentication session.
        /// </returns>
        /// <exception cref="ArgumentNullException">requestQuery</exception>
        /// <exception cref="InvalidOperationException">No Options found for authentication!</exception>
        /// <exception cref="OpenIdConnectProtocolException">Error in the authorization response: " + authorizationResponse.Error</exception>
        /// <exception cref="ArgumentException">
        /// requestQuery
        /// or
        /// Invalid request properties
        /// or
        /// requestQuery
        /// or
        /// Invalid state!
        /// </exception>
        public async Task<AuthenticationProperties> ValidateAuthorization(IQueryCollection requestQuery, string redirectUri = "")
        {
            if (requestQuery == null)
            {
                throw new ArgumentNullException("requestQuery");
            }

            if (Options == null)
            {
                throw new InvalidOperationException("No Options found for authentication!");
            }

            OpenIdConnectMessage authorizationResponse = new OpenIdConnectMessage(requestQuery.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            AuthenticationProperties properties = ValidateAndFillResponseProperties(authorizationResponse);
            return properties == null ? null : await ValidateAuthorizationCode(authorizationResponse.Code, string.Empty, redirectUri, properties);
        }

        /// <summary>
        /// Returns the authentication properties of the response when the validation of the specified code value succeeds and
        /// the user identifier, if passed, corresponds to the identity token one.
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="userId">The user identifier expected to be returned in the token.</param>
        /// <param name="redirectUri">(Optional) The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <param name="properties">The authentication properties for the response. If specified, they are modified with the response data.</param>
        /// <returns>
        /// The properties of the authentication response.
        /// </returns>
        /// <exception cref="ArgumentNullException">MiraclOptions should be set!</exception>
        /// <exception cref="System.ArgumentException">Empty redirect uri!
        /// or
        /// Invalid token data!
        /// or
        /// Invalid nonce</exception>
        public async Task<AuthenticationProperties> ValidateAuthorizationCode(string code, string userId, string redirectUri = "", AuthenticationProperties properties = null)
        {
            if (this.Options == null)
            {
                throw new ArgumentNullException("MiraclOptions should be set!");
            }

            this.TokenEndpointResponse = await RedeemAuthorizationCodeAsync(code, redirectUri);
            properties = properties ?? new AuthenticationProperties();

            if (!IsResponseValid(properties, userId))
            {
                return null;
            }

            if (this.Options.SaveTokens)
            {
                SaveTokens(properties, this.TokenEndpointResponse);
            }

            return properties;
        }

        /// <summary>
        /// Gets the claims-based identity given by the authentication.
        /// </summary>
        /// <param name="claimsIssuer">The claims issuer of the authentication.</param>
        /// <returns>
        /// The claims-based identity for granting the user to be signed in.
        /// </returns>
        /// <exception cref="ArgumentNullException">MiraclOptions should be set!</exception>
        /// <exception cref="InvalidOperationException">ValidateAuthorization method should be called first!</exception>
        public async Task<ClaimsPrincipal> GetIdentity(string claimsIssuer = null)
        {
            if (this.Options == null)
            {
                throw new ArgumentNullException("MiraclOptions should be set!");
            }

            if (this.TokenEndpointUser == null || this.TokenEndpointUser.Identity == null)
            {
                throw new InvalidOperationException("ValidateAuthorization method should be called first!");
            }

            var userInfoEndpoint = this.Options.Configuration?.UserInfoEndpoint;
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", this.TokenEndpointResponse.AccessToken);
            var responseMessage = await Options.Backchannel.SendAsync(requestMessage);
            responseMessage.EnsureSuccessStatusCode();

            var userInfoResponse = await responseMessage.Content.ReadAsStringAsync();

            var contentType = responseMessage.Content.Headers.ContentType;
            if (contentType.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
            {
                this.UserJson = JObject.Parse(userInfoResponse);
            }          
            else
            {
                return null;
            }

            this.Options.ProtocolValidator.ValidateUserInfoResponse(new OpenIdConnectProtocolValidationContext()
            {
                UserInfoEndpointResponse = userInfoResponse,
                ValidatedIdToken = this.IdTokenEndpointJwt,
            });

            // create a new identity by the existing this.TokenEndpointUser.Identity so we could add some ours claims
            List<Claim> claims = CreateAdditionalClaims(claimsIssuer);
            var identity = new ClaimsIdentity(this.TokenEndpointUser.Identity, claims);

            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Clears the user authorization information.
        /// </summary>
        /// <param name="includingAuth">if set to <c>true</c> the user authentication data is also cleaned.</param>
        public void ClearUserInfo(bool includingAuth = true)
        {
            if (includingAuth)
            {
                this.UserState = null;
                this.Nonce = null;
                this.Options = null;
            }

            this.CallbackUrl = null;
            this.UserJson = null;
            this.TokenEndpointUser = null;
            this.TokenEndpointResponse = null;
            this.IdTokenEndpointJwt = null;
            this.State = null;
        }

        /// <summary>
        /// Sends signature for verification to the DVS (designated verifier scheme) service and verifies the received response.
        /// </summary>
        /// <param name="signature">The signature to be verified.</param>
        /// <param name="ts">Timestamp showing when the signature was made.</param>
        /// <returns><para cref="VerificationResult"/> object which indicates if the specified signature is properly signed.</returns>
        /// <exception cref="ArgumentNullException">Signature cannot be null or empty</exception> 
        /// <exception cref="InvalidOperationException">No Options for verification - client credentials are used for the verification</exception>
        /// <exception cref="ArgumentException">
        /// Timestamp cannot has a negative value
        /// or
        /// DVS public key not found
        /// or
        /// No `certificate` in the JSON response
        /// or
        /// Invalid DVS token format
        /// or
        /// No `hash` in the JWT payload
        /// or
        /// No `hash` in the signature
        /// or
        /// Signature hash and response hash do not match
        /// or
        /// No `cAt` in the signature
        /// or
        /// The transaction is signed before the issue time
        /// </exception>
        public async Task<VerificationResult> DvsVerifySignature(Signature signature, int ts)
        {
            ValidateInput(signature, ts);

            var p = new Payload
            {
                Signature = signature,
                Timestamp = ts,
                Type = "verification"
            };

            var resp = await RequestSignature(p);
            string respContent;
            switch (resp.StatusCode)
            {
                case System.Net.HttpStatusCode.OK:
                    respContent = await resp.Content.ReadAsStringAsync();
                    break;
                case System.Net.HttpStatusCode.Unauthorized:
                    return new VerificationResult() { Status = VerificationStatus.BadPin, IsSignatureValid = false };
                case System.Net.HttpStatusCode.Gone:
                    return new VerificationResult() { Status = VerificationStatus.UserBlocked, IsSignatureValid = false };
                default:
                    return new VerificationResult() { Status = VerificationStatus.MissingSignature, IsSignatureValid = false };
            }

            bool isValid = VerifyResponseSignature(p, respContent);
            var status = isValid ? VerificationStatus.ValidSignature : VerificationStatus.InvalidSignature;
            return new VerificationResult() { Status = status, IsSignatureValid = isValid };
        }

        /// <summary>
        /// Creates a document hash using the SHA256 hashing algorithm.
        /// </summary>
        /// <param name="document">A generic document.</param>
        /// <returns>Hash value of the document as a hex-encoded string</returns>
        public string DvsCreateDocumentHash(string document)
        {
            using (var algorithm = SHA256.Create())
            {
                var hashedBytes = algorithm.ComputeHash(Encoding.UTF8.GetBytes(document));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }

        #endregion

        #region Private
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system to be redirected to.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        /// <param name="options">The options.</param>
        /// <param name="userStateString">(Optional) The state string. If not specified, the user state is internally generated.</param>
        /// <returns>Uri for authorization to be redirected to.</returns>
        /// <exception cref="System.ArgumentException">MiraclOptions should be set!</exception>
        private string GetAuthorizationRequestUrl(string baseUri, AuthenticationProperties properties, string userStateString = null)
        {
            this.CallbackUrl = baseUri.TrimEnd('/') + this.Options.CallbackPath;
            string scope = this.Options.Scope.Count() > 0 ? string.Join(" ", Options.Scope) : Constants.Scope;
            if (Options.ProtocolValidator.RequireNonce)
            {
                this.Nonce = Options.ProtocolValidator.GenerateNonce();
            }
            this.UserState = userStateString ?? Guid.NewGuid().ToString("N");
            var message = new OpenIdConnectMessage
            {
                ClientId = Options.ClientId,
                EnableTelemetryParameters = !Options.DisableTelemetry,
                RedirectUri = this.CallbackUrl,
                Resource = Options.Resource,
                ResponseType = Constants.Code,
                IssuerAddress = this.Options.Configuration.AuthorizationEndpoint,
                Scope = scope,
                Nonce = this.Nonce
            };
            
            if (properties == null)
            {
                properties = new AuthenticationProperties
                {
                    RedirectUri = this.CallbackUrl
                };
            }

            properties.Items.Add(OpenIdConnectDefaults.UserstatePropertiesKey, this.UserState);
            // When redeeming a 'code' for an AccessToken, this value is needed
            properties.Items.Add(OpenIdConnectDefaults.RedirectUriForCodePropertiesKey, message.RedirectUri);
            message.State = this.State = this.Options.StateDataFormat.Protect(properties);

            var authUrl = message.CreateAuthenticationRequestUrl();
            return authUrl;
        }
        
        private async Task LoadOpenIdConnectConfigurationAsync()
        {
            if (!this.Options.IsConfigured)
            {
                MiraclPostConfigureOptions o = new MiraclPostConfigureOptions(null);
                o.PostConfigure(Constants.AuthenticationScheme, this.Options);
            }

            if (this.Options != null && this.Options.Configuration == null && this.Options.ConfigurationManager != null)
            {
                this.Options.Configuration = await this.Options.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
            }

            if (this.Options != null && this.Options.DvsConfiguration == null && this.Options.DvsConfigurationManager != null)
            {
                this.Options.DvsConfiguration = await this.Options.DvsConfigurationManager.GetConfigurationAsync(CancellationToken.None);
                ParseSecurityKey();
            }
        }
        
        internal void ParseSecurityKey()
        {
            if (this.Options == null || this.Options.DvsConfiguration == null ||
                this.Options.DvsConfiguration.AdditionalData.Count() != 1)
            {
                throw new ArgumentNullException("Invalid dvs key!");
            }

            JArray keyParams = this.Options.DvsConfiguration.AdditionalData.First().Value as JArray;
            if (keyParams == null || keyParams.Count() != 1)
            {
                throw new ArgumentNullException("Invalid dvs key!");
            }

            string id = string.Empty;
            var dvsRsaParameters = new RSAParameters();
            foreach (JProperty p in keyParams.First())
            {
                switch (p.Name)
                {
                    case "e":
                        dvsRsaParameters.Exponent = Base64UrlEncoder.DecodeBytes(p.Value.ToString());
                        break;
                    case "n":
                        dvsRsaParameters.Modulus = Base64UrlEncoder.DecodeBytes(p.Value.ToString());
                        break;
                    case "kid":
                        id = p.Value.ToString();
                        break;
                    case "kty":
                        if (p.Value.ToString() != "RSA")
                        {
                            throw new ArgumentException("Invalid dvs key!");
                        }
                        break;
                }
            }

            this.Options.DvsConfiguration.SigningKeys.Add(new RsaSecurityKey(dvsRsaParameters) { KeyId = id });
        }

        // Note this modifies the properties if Options.UseTokenLifetime
        private ClaimsPrincipal ValidateIdToken(AuthenticationProperties properties, TokenValidationParameters validationParameters, out JwtSecurityToken jwt)
        {
            string idToken = this.TokenEndpointResponse.IdToken;
            if (!Options.SecurityTokenValidator.CanReadToken(idToken))
            {
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "Unable to read id token", idToken));
            }

            if (this.Options.Configuration != null)
            {
                var issuer = new[] { this.Options.Configuration.Issuer };
                validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuer) ?? issuer;
                validationParameters.ValidateAudience = true;
                validationParameters.ValidateIssuer = true;
                validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(this.Options.Configuration.SigningKeys)
                    ?? this.Options.Configuration.SigningKeys;
            }
             
            var principal = this.Options.SecurityTokenValidator.ValidateToken(idToken, validationParameters, out SecurityToken validatedToken);
            if (validatedToken == null)
            {
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "Unable To Validate Token", idToken));
            }

            jwt = validatedToken as JwtSecurityToken;
            if (jwt == null)
            {
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "Validated Security Token is Not Jwt", validatedToken?.GetType()));
            }

            if (Options.UseTokenLifetime)
            {
                var issued = validatedToken.ValidFrom;
                if (issued != DateTime.MinValue)
                {
                    properties.IssuedUtc = issued;
                }

                var expires = validatedToken.ValidTo;
                if (expires != DateTime.MinValue)
                {
                    properties.ExpiresUtc = expires;
                }
            }

            return principal;
        }

        internal string TryGetValue(string propertyName)
        {
            if (this.UserJson == null)
                return string.Empty;

            JToken value;
            return this.UserJson.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        private void SaveTokens(AuthenticationProperties properties, OpenIdConnectMessage message)
        {
            var tokens = new List<AuthenticationToken>();
            AddToken(message.AccessToken, OpenIdConnectParameterNames.AccessToken, tokens);
            AddToken(message.IdToken, OpenIdConnectParameterNames.IdToken, tokens);
            AddToken(message.RefreshToken, OpenIdConnectParameterNames.RefreshToken, tokens);
            AddToken(message.TokenType, OpenIdConnectParameterNames.TokenType, tokens);

            if (!string.IsNullOrEmpty(message.ExpiresIn))
            {
                if (int.TryParse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                {
                    var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(value);
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    tokens.Add(new AuthenticationToken { Name = Constants.ExpiresAt, Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) });
                }
            }

            properties.StoreTokens(tokens);
        }

        private void AddToken(string token, string name, List<AuthenticationToken> tokens)
        {
            if (!string.IsNullOrEmpty(token))
            {
                tokens.Add(new AuthenticationToken { Name = name, Value = token });
            }
        }

        private async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync(string code, string redirectUri)
        {
            var tokenEndpointRequest = new OpenIdConnectMessage()
            {
                ClientId = this.Options.ClientId,
                ClientSecret = this.Options.ClientSecret,
                Code = code,
                GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
                EnableTelemetryParameters = !this.Options.DisableTelemetry,
                RedirectUri = string.IsNullOrEmpty(redirectUri) ? this.CallbackUrl : redirectUri,
            };

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.Configuration.TokenEndpoint);
            requestMessage.Content = new FormUrlEncodedContent(tokenEndpointRequest.Parameters);

            var responseMessage = await this.Options.Backchannel.SendAsync(requestMessage);

            // Error handling:
            // 1. If the response body can't be parsed as json, throws.
            // 2. If the response's status code is not in 2XX range, throw OpenIdConnectProtocolException. If the body is correct parsed,
            //    pass the error information from body to the exception.
            OpenIdConnectMessage tokenEndpointResponse = null;
            try
            {
                var responseContent = await responseMessage.Content.ReadAsStringAsync();
                tokenEndpointResponse = new OpenIdConnectMessage(responseContent);
            }
            catch (Exception ex)
            {
                throw new OpenIdConnectProtocolException($"Failed to parse token response body as JSON. Status Code: {(int)responseMessage.StatusCode}. Content-Type: {responseMessage.Content.Headers.ContentType}", ex);
            }

            if (!responseMessage.IsSuccessStatusCode)
            {
                throw new OpenIdConnectProtocolException(string.Format(
                        CultureInfo.InvariantCulture,
                        "Message contains error: '{0}', error_description: '{1}', error_uri: '{2}'.",
                        tokenEndpointResponse.Error,
                        tokenEndpointResponse.ErrorDescription ?? "error_description is null",
                        tokenEndpointResponse.ErrorUri ?? "error_uri is null"));
            }

            return tokenEndpointResponse;
        }
        
        private AuthenticationProperties ValidateAndFillResponseProperties(OpenIdConnectMessage authorizationResponse)
        {
            if (!string.IsNullOrEmpty(authorizationResponse.Error))
            {
                throw new OpenIdConnectProtocolException("Error in the authorization response: " + authorizationResponse.Error);
            }

            string code = authorizationResponse.Code;
            // Fail if state is missing, it's required for the correlation id.
            if (string.IsNullOrEmpty(authorizationResponse.State) || string.IsNullOrEmpty(code))
            {
                if (this.Options.SkipUnrecognizedRequests)
                {
                    return null;
                }

                throw new ArgumentException(
                        string.Format("requestQuery does not have the proper \"{0}\" and \"{1}\" parameteres.", Constants.Code, Constants.State), "requestQuery");
            }

            // if state exists and we failed to 'unprotect' this is not a message we should process.
            AuthenticationProperties properties = Options.StateDataFormat.Unprotect(authorizationResponse.State);
            if (properties == null)
            {
                if (this.Options.SkipUnrecognizedRequests)
                {
                    return null;
                }
                throw new ArgumentException("Invalid request properties");
            }

            properties.Items.TryGetValue(OpenIdConnectDefaults.UserstatePropertiesKey, out string userstate);
            authorizationResponse.State = userstate;

            string returnedState = authorizationResponse.State;
            if (string.IsNullOrEmpty(returnedState))
            {
                throw new ArgumentException(
                    string.Format("requestQuery does not have the proper \"{0}\" and \"{1}\" parameteres.", Constants.Code, Constants.State), "requestQuery");
            }

            if (!this.UserState.Equals(returnedState, StringComparison.Ordinal))
            {
                throw new ArgumentException("Invalid state!");
            }

            PopulateSessionProperties(authorizationResponse, properties);

            return properties;
        }

        private void PopulateSessionProperties(OpenIdConnectMessage message, AuthenticationProperties properties)
        {
            if (!string.IsNullOrEmpty(message.SessionState))
            {
                properties.Items[OpenIdConnectSessionProperties.SessionState] = message.SessionState;
            }

            if (!string.IsNullOrEmpty(this.Options.Configuration.CheckSessionIframe))
            {
                properties.Items[OpenIdConnectSessionProperties.CheckSessionIFrame] = this.Options.Configuration.CheckSessionIframe;
            }
        }
                
        private bool IsResponseValid(AuthenticationProperties properties, string userId)
        {
            if (this.TokenEndpointResponse == null || this.TokenEndpointResponse.AccessToken == null || string.IsNullOrEmpty(this.TokenEndpointResponse.IdToken))
            {
                throw new ArgumentException("Invalid token data!");
            }

            if (!IsUserIdValid(userId))
            {
                return false;
            }

            var validationParameters = Options.TokenValidationParameters.Clone();
            this.TokenEndpointUser = ValidateIdToken(properties, validationParameters, out this.IdTokenEndpointJwt);

            var receivedNonce = this.IdTokenEndpointJwt.Payload.Nonce;
            if (receivedNonce != this.Nonce)
            {
                throw new ArgumentException("Invalid nonce");
            }

            this.Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext()
            {
                ClientId = this.Options.ClientId,
                ProtocolMessage = this.TokenEndpointResponse,
                ValidatedIdToken = this.IdTokenEndpointJwt,
                Nonce = this.Nonce
            });

            return true;
        }

        private bool IsUserIdValid(string userId)
        {
            bool isUserIdValid = true;
            if (!string.IsNullOrEmpty(userId) && this.TokenEndpointResponse.IdToken != null)
            {
                isUserIdValid = userId == GetUserId();
            }

            return isUserIdValid;
        }

        private string GetUserId()
        {
            var idToken = ParseJwt(this.TokenEndpointResponse.IdToken);
            var id = idToken.GetValue("sub");
            return id == null ? string.Empty : id.ToString();
        }

        private JObject ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                throw new ArgumentException("Wrong token data!");
            }

            var parts = token.Split('.');
            var p = Base64UrlEncoder.DecodeBytes(parts[1]);
            var part = Encoding.UTF8.GetString(p);
            return JObject.Parse(part);
        }

        private List<Claim> CreateAdditionalClaims(string claimsIssuer)
        {
            var claims = new List<Claim>();
            var tokenClaims = (this.TokenEndpointUser.Identity as ClaimsIdentity).Claims;
            claims.Add(new Claim(ClaimTypes.Email, this.Email, claimsIssuer));
            claims.Add(new Claim(Constants.AccessToken, TokenEndpointResponse.AccessToken, claimsIssuer));
            claims.Add(new Claim(Constants.ExpiresAt, DateTime.UtcNow.AddSeconds(double.Parse(TokenEndpointResponse.ExpiresIn)).ToString(), claimsIssuer));

            if (!string.IsNullOrWhiteSpace(TokenEndpointResponse.RefreshToken))
            {
                claims.Add(new Claim(Constants.RefreshToken, TokenEndpointResponse.RefreshToken, claimsIssuer));
            }

            AddUserInfoClaimsAsync(claimsIssuer);

            return claims;
        }

        // add user claims from the json to the authenticated identity
        private void AddUserInfoClaimsAsync(string claimsIssuer)
        {
            var identity = this.TokenEndpointUser.Identity as ClaimsIdentity;
            if (!this.Options.GetClaimsFromUserInfoEndpoint)
            {
                foreach (var action in Options.ClaimActions)
                {
                    action.Run(null, identity, claimsIssuer);
                }
            }
            else if (claimsIssuer != null && identity != null)
            {
                foreach (var action in this.Options.ClaimActions)
                {
                    action.Run(this.UserJson, identity, claimsIssuer);
                }
            }
        }

        #region dvs
        private void ValidateInput(Signature signature, int ts)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("Signature cannot be null");
            }

            if (ts < 0)
            {
                throw new ArgumentException("Timestamp cannot has a negative value");
            }

            if (this.Options == null)
            {
                throw new InvalidOperationException("No Options for verification - client credentials are used for the verification");
            }

            if (this.Options.DvsConfiguration == null || this.Options.DvsConfiguration.SigningKeys == null || this.Options.DvsConfiguration.SigningKeys.Count < 1)
            {
                throw new ArgumentException("DVS public key not found");
            }
        }

        private async Task<HttpResponseMessage> RequestSignature(Payload p)
        {
            var payloadString = JsonConvert.SerializeObject(p);
            var content = new StringContent(payloadString, Encoding.UTF8, "application/json");

            var byteArray = Encoding.ASCII.GetBytes(this.Options.ClientId + ":" + this.Options.ClientSecret);
            this.Options.Backchannel.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
            this.Options.Backchannel.DefaultRequestHeaders.Add("Accept", "text/plain");
            return await this.Options.Backchannel.PostAsync(this.Options.Authority + Constants.DvsVerifyString, content);
        }

        private bool VerifyResponseSignature(Payload p, string respContent)
        {
            JToken certToken;
            if (!JObject.Parse(respContent).TryGetValue("certificate", out certToken))
            {
                throw new ArgumentException("No `certificate` in the JSON response");
            }
            var respToken = certToken.ToString();
            
            var parts = respToken.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Invalid DVS token format");
            }

            byte[] jwtSignature = Base64UrlEncoder.DecodeBytes(parts[2]);

            var jwtPayload = ParseJwt(respToken);
            JToken hashToken;
            if (!jwtPayload.TryGetValue("hash", out hashToken))
            {
                throw new ArgumentException("No `hash` in the JWT payload");
            }

            var hash = hashToken.ToString();
            var docHash = p.Signature.Hash;
            if (!docHash.Equals(hash))
            {
                throw new ArgumentException("Signature hash and response hash do not match");
            }

            JToken cAtToken;
            if (!jwtPayload.TryGetValue("cAt", out cAtToken))
            {
                throw new ArgumentException("No `cAt` in the signature");
            }
            int cAt;
            if (!int.TryParse(cAtToken.ToString(), out cAt))
            {
                throw new ArgumentException("Invalid `cAt` value");
            }

            if (p.Timestamp > cAt)
            {
                throw new ArgumentException("The transaction is signed before the issue time");
            }

            var dvsRsaParameters = (this.Options.DvsConfiguration.SigningKeys.First() as RsaSecurityKey).Parameters;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(dvsRsaParameters);
                return rsa.VerifyData(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]), jwtSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }      
        #endregion
        #endregion
        #endregion
    }
}
