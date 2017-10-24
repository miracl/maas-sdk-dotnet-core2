using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Miracl
{
    /// <summary>
    /// Extensions for authentication against the MIRACL server.
    /// </summary>
    public static class MiraclExtension
    {
        /// <summary>
        /// Adds the miracl authentication with the specified <see cref="MiraclOptions"/> to the specified <see cref="AuthenticationBuilder" />.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configureOptions">The <see cref="MiraclOptions"/> to use for authentication.</param>
        /// <returns>An <see cref="AuthenticationBuilder" /> setup to authenticate against the MIRACL server.</returns>
        public static AuthenticationBuilder AddMiracl(this AuthenticationBuilder builder, Action<MiraclOptions> configureOptions)
            => builder.AddMiracl(Constants.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds the miracl authentication with the specified <see cref="MiraclOptions"/> and authentication schema 
        /// to the specified <see cref="AuthenticationBuilder" />.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The <see cref="MiraclOptions"/> to use for authentication.</param>
        /// <returns>An <see cref="AuthenticationBuilder" /> setup to authenticate against the MIRACL server.</returns>        
        public static AuthenticationBuilder AddMiracl(this AuthenticationBuilder builder, string authenticationScheme, Action<MiraclOptions> configureOptions)
            => builder.AddMiracl(authenticationScheme, Constants.DisplayName, configureOptions);

        /// <summary>
        /// Adds the miracl authentication with the specified <see cref="MiraclOptions"/>, authentication schema and display name
        /// to the specified <see cref="AuthenticationBuilder" />.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The <see cref="MiraclOptions"/> to use for authentication.</param>
        /// <returns>An <see cref="AuthenticationBuilder" /> setup to authenticate against the MIRACL server.</returns>        
        public static AuthenticationBuilder AddMiracl(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<MiraclOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<MiraclOptions>, MiraclPostConfigureOptions>());
            return builder.AddRemoteScheme<MiraclOptions, MiraclHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
