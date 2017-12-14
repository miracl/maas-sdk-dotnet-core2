using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Miracl
{
    /// <summary>
    /// Configuration options for <see cref="MiraclHandler"/>
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions" />
    public class MiraclOptions : OpenIdConnectOptions
    {
        // used to post configure the options when used in manual authentication
        internal bool IsConfigured = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclOptions"/> class.
        /// </summary>
        /// <remarks>
        /// Defaults:
        /// <para>AddNonceToRequest: true.</para><para>BackchannelTimeout: 1 minute.</para><para>ProtocolValidator: new <see cref="T:Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectProtocolValidator" />.</para><para>RefreshOnIssuerKeyNotFound: true</para><para>ResponseType: <see cref="F:Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseType.CodeIdToken" /></para><para>Scope: <see cref="F:Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectScope.OpenIdProfile" />.</para><para>TokenValidationParameters: new <see cref="P:Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions.TokenValidationParameters" /> with AuthenticationScheme = authenticationScheme.</para><para>UseTokenLifetime: false.</para>
        /// </remarks>
        public MiraclOptions()
        {
            this.CallbackPath = new PathString(Constants.CallbackString);
        }
                
        // Summary:
        //     Responsible for retrieving, caching, and refreshing the DVS configuration from metadata.
        //     If not provided, then one will be created using the DVS MetadataAddress and Backchannel
        //     properties.
        public IConfigurationManager<OpenIdConnectConfiguration> DvsConfigurationManager { get; set; }

        //
        // Summary:
        //     Configuration provided directly by the developer. If provided, then DVS MetadataAddress
        //     and the Backchannel properties will not be used. This information should not
        //     be updated during request processing.
        public OpenIdConnectConfiguration DvsConfiguration { get; set; }

        /// <summary>
        /// Gets or sets the customer identifier registered in the MIRACL platform.
        /// </summary>
        /// <value>
        /// The customer identifier.
        /// </value>
        public string CustomerId { get; set; }
    }
}
