using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Miracl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;

namespace MiraclAuthenticationTests
{
    internal class TestSettings
    {
        private readonly Action<MiraclOptions> _configureOptions;

        public TestSettings() : this(configure: null)
        {
        }

        public TestSettings(Action<MiraclOptions> configure)
        {
            _configureOptions = o =>
            {
                configure?.Invoke(o);
                _options = o;
            };
        }

        public string ExpectedState { get; set; }

        public UrlEncoder Encoder => UrlEncoder.Default;

        public TestServer CreateTestServer(AuthenticationProperties properties = null) => TestServerBuilder.CreateServer(_configureOptions, handler: null, properties: properties);

        public IDictionary<string, string> ValidateChallengeRedirect(Uri redirectUri, params string[] parametersToValidate) =>
                ValidateRedirectCore(redirectUri, OpenIdConnectRequestType.Authentication, parametersToValidate);

        private IDictionary<string, string> ValidateRedirectCore(Uri redirectUri, OpenIdConnectRequestType requestType, string[] parametersToValidate)
        {
            var errors = new List<string>();

            // Validate the authority
            ValidateExpectedAuthority(redirectUri.AbsoluteUri, errors, requestType);

            // Convert query to dictionary
            var queryDict = string.IsNullOrEmpty(redirectUri.Query) ?
                new Dictionary<string, string>() :
                redirectUri.Query.TrimStart('?').Split('&').Select(part => part.Split('=')).ToDictionary(parts => parts[0], parts => parts[1]);

            // Validate the query string parameters
            ValidateParameters(queryDict, parametersToValidate, errors, htmlEncoded: true);

            if (errors.Any())
            {
                var buf = new StringBuilder();
                buf.AppendLine($"The redirect uri is not valid.");
                buf.AppendLine(redirectUri.AbsoluteUri);

                foreach (var error in errors)
                {
                    buf.AppendLine(error);
                }

                Assert.IsTrue(false, buf.ToString());
            }

            return queryDict;
        }

        private void ValidateParameters(
            IDictionary<string, string> actualValues,
            IEnumerable<string> parametersToValidate,
            ICollection<string> errors,
            bool htmlEncoded)
        {
            foreach (var paramToValidate in parametersToValidate)
            {
                switch (paramToValidate)
                {
                    case OpenIdConnectParameterNames.ClientId:
                        ValidateClientId(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.ResponseType:
                        ValidateResponseType(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.Scope:
                        ValidateScope(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.RedirectUri:
                        ValidateRedirectUri(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.Resource:
                        ValidateResource(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.State:
                        ValidateState(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.SkuTelemetry:
                        ValidateSkuTelemetry(actualValues, errors, htmlEncoded);
                        break;
                    case OpenIdConnectParameterNames.VersionTelemetry:
                        ValidateVersionTelemetry(actualValues, errors, htmlEncoded);
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown parameter \"{paramToValidate}\".");
                }
            }
        }

        MiraclOptions _options = null;

        private void ValidateClientId(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.ClientId, _options.ClientId, actualQuery, errors, htmlEncoded);

        private void ValidateResponseType(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.ResponseType, _options.ResponseType, actualQuery, errors, htmlEncoded);

        private void ValidateScope(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.Scope, string.Join(" ", _options.Scope), actualQuery, errors, htmlEncoded);

        private void ValidateRedirectUri(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.RedirectUri, TestServerBuilder.TestHost + _options.CallbackPath, actualQuery, errors, htmlEncoded);

        private void ValidateResource(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.RedirectUri, _options.Resource, actualQuery, errors, htmlEncoded);

        private void ValidateState(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.State, ExpectedState, actualQuery, errors, htmlEncoded);

        private void ValidateSkuTelemetry(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.SkuTelemetry, "ID_NET", actualQuery, errors, htmlEncoded);

        private void ValidateVersionTelemetry(IDictionary<string, string> actualQuery, ICollection<string> errors, bool htmlEncoded) =>
            ValidateQueryParameter(OpenIdConnectParameterNames.VersionTelemetry, typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString(), actualQuery, errors, htmlEncoded);

        private void ValidateQueryParameter(
            string parameterName,
            string expectedValue,
            IDictionary<string, string> actualQuery,
            ICollection<string> errors,
            bool htmlEncoded)
        {
            string actualValue;
            if (actualQuery.TryGetValue(parameterName, out actualValue))
            {
                if (htmlEncoded)
                {
                    expectedValue = Encoder.Encode(expectedValue);
                }

                if (actualValue != expectedValue)
                {
                    errors.Add($"Query parameter {parameterName}'s expected value is {expectedValue} but its actual value is {actualValue}");
                }
            }
            else
            {
                errors.Add($"Query parameter {parameterName} is missing");
            }
        }

        private void ValidateExpectedAuthority(string absoluteUri, ICollection<string> errors, OpenIdConnectRequestType requestType)
        {
            string expectedAuthority;
            switch (requestType)
            {
                case OpenIdConnectRequestType.Token:
                    expectedAuthority = _options.Configuration?.TokenEndpoint ?? _options.Authority + @"/oauth2/token";
                    break;
                case OpenIdConnectRequestType.Logout:
                    expectedAuthority = _options.Configuration?.EndSessionEndpoint ?? _options.Authority + @"/oauth2/logout";
                    break;
                default:
                    expectedAuthority = _options.Configuration?.AuthorizationEndpoint ?? _options.Authority + @"/oauth2/authorize";
                    break;
            }

            if (!absoluteUri.StartsWith(expectedAuthority))
            {
                errors.Add($"ExpectedAuthority: {expectedAuthority}");
            }
        }
    }
}
