using Newtonsoft.Json;

namespace Miracl
{
    /// <summary>
    /// Contains the parameters used for identity activation.
    /// </summary>
    public class IdentityActivationParams
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityActivationParams"/> class.
        /// </summary>
        /// <param name="mPinIdHash">The hash of the M-PIN id.</param>
        /// <param name="activateKey">The key used to activate the identity.</param>
        public IdentityActivationParams([JsonProperty("hashMPinID")] string mPinIdHash, string activateKey)
        {
            this.MPinIdHash = mPinIdHash;
            this.ActivateKey = activateKey;
        }

        /// <summary>
        /// Gets the hash of the M-PIN id.
        /// </summary>
        /// <value>
        /// The hash of the M-PIN id.
        /// </value>
        [JsonProperty("hashMPinID")]
        public string MPinIdHash { get; private set; }

        /// <summary>
        /// Gets the activate key.
        /// </summary>
        /// <value>
        /// The activate key.
        /// </value>
        public string ActivateKey { get; private set; }
    }
}
