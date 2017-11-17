using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Miracl;
using NUnit.Framework;
using System;
using static Miracl.MiraclPostConfigureOptions;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclConfigurationTests
    {
        [Test]
        public void Test_PostConfigure_MetadataAddressIsGeneratedFromAuthorityWhenMissing()
        {
            var options = new MiraclOptions();
            options.Authority = TestServerBuilder.DefaultAuthority;

            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options);
            Assert.That(options.MetadataAddress, Is.EqualTo($"{TestServerBuilder.DefaultAuthority}/.well-known/openid-configuration"));
        }

        [Test]
        public void Test_PostConfigure_SetAuthorityToServerBaseAddressWhenAuthorityIsMissing()
        {
            var options = new MiraclOptions();

            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options);
            Assert.That(options.Authority, Is.EqualTo(Constants.ServerBaseAddress));
        }

        [Test]
        public void Test_PostConfigure_ThrowsWhenAuthorityIsNotHttps()
        {
            var options = new MiraclOptions();
            options.Authority = "http://example.com";

            Assert.That(() => new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options),
                Throws.TypeOf<InvalidOperationException>()
                .And.Message.EqualTo("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false."));
        }

        [Test]
        public void Test_PostConfigure_ThrowsWhenMetadataAddressIsNotHttps()
        {
            var options = new MiraclOptions();
            options.MetadataAddress = "http://example.com";

            Assert.That(() => new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options),
                Throws.TypeOf<InvalidOperationException>()
                .And.Message.EqualTo("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false."));
        }

        [Test]
        public void Test_PostConfigure_MetadataAddressShouldBeTrimmedWhenEndsWithSlash()
        {
            var options = new MiraclOptions();
            options.Authority = "https://example.com/";

            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options);
            Assert.That(options.MetadataAddress, Is.EqualTo("https://example.com/.well-known/openid-configuration"));
        }

        [Test]
        public void Test_PostConfigure_SettingDvsConfigShouldSetDvsConfigurationManager()
        {
            var options = new MiraclOptions();
            options.DvsConfiguration = new OpenIdConnectConfiguration();

            Assert.That(options.DvsConfigurationManager, Is.Null);
            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, options);
            Assert.That(options.DvsConfigurationManager, Is.Not.Null);
        }

        [Test]
        public void Test_StringSerializer()
        {
            var s = new StringSerializer();
            var data = "abc";
            var dataBytes = new byte[] { 97, 98, 99};
            Assert.That(s.Serialize(data), Is.EqualTo(dataBytes));
            Assert.That(s.Deserialize(dataBytes), Is.EqualTo(data));
        }
    }
}
