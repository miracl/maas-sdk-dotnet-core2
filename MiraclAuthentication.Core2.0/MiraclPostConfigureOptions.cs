using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Net.Http;
using System.Text;

namespace Miracl
{
    /// <summary>
    /// Used to setup defaults for all <see cref="MiraclOptions"/>.
    /// </summary>
    /// <seealso cref="Microsoft.Extensions.Options.IPostConfigureOptions{Miracl.MiraclOptions}" />
    public class MiraclPostConfigureOptions : IPostConfigureOptions<MiraclOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public MiraclPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        /// <summary>
        /// Invoked to post configure a <see cref="MiraclOptions"/> instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        /// <exception cref="InvalidOperationException">The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.</exception>
        public void PostConfigure(string name, MiraclOptions options)
        {                                   
            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            options.DataProtectionProvider = options.DataProtectionProvider ?? new EphemeralDataProtectionProvider();
            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                                    typeof(MiraclClient).FullName, Constants.AuthenticationScheme, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            
            if (options.StringDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(MiraclClient).FullName,
                    typeof(string).FullName,
                    name,
                    "v1");

                options.StringDataFormat = new SecureDataFormat<string>(new StringSerializer(), dataProtector);
            }
    
            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
                }
                else
                {
                    if (string.IsNullOrEmpty(options.Authority))
                    {
                        options.Authority = Constants.ServerBaseAddress;
                    }

                    if (string.IsNullOrEmpty(options.MetadataAddress) && !string.IsNullOrEmpty(options.Authority))
                    {
                        options.MetadataAddress = options.Authority;
                        if (options.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                        {
                            options.MetadataAddress = options.MetadataAddress.TrimEnd('/');
                        }

                        options.MetadataAddress += Constants.DiscoveryPath;
                    }

                    if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                    }

                    options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                        new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata });                    
                }
            }

            if (options.DvsConfigurationManager == null)
            {
                if (options.DvsConfiguration != null)
                {
                    options.DvsConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.DvsConfiguration);
                }
                else
                {                    
                    options.DvsConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.Authority + Constants.DvsPublicKeyString, new OpenIdConnectConfigurationRetriever(),
                        new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata });
                }
            }
            
            options.IsConfigured = true;
        }

        internal class StringSerializer : IDataSerializer<string>
        {
            public string Deserialize(byte[] data)
            {
                return Encoding.UTF8.GetString(data);
            }

            public byte[] Serialize(string model)
            {
                return Encoding.UTF8.GetBytes(model);
            }
        }
    }
}
