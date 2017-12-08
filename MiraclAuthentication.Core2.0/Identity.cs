using Newtonsoft.Json;
using System;

namespace Miracl
{
    /// <summary>
    /// Describes the identity object used for registration.
    /// </summary>
    public class Identity
    {
        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="Identity"/> class.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <param name="deviceName">Name of the device.</param>
        /// <param name="mPinIdHash">The hash of the M-PIN id.</param>
        /// <param name="activateKey">The key used to activate the identity.</param>
        /// <param name="activateExpireTime">Timestamp used to determine if a registration session is still active.</param>
        public Identity([JsonProperty("userId")] string id, string deviceName, string mPinIdHash, string activateKey, Int64 activateExpireTime)
        {
            this.Info = new IdentityInfo(id, deviceName);
            this.MPinIdHash = mPinIdHash;
            this.ActivateKey = activateKey;
            this.ActivateExpireTime = activateExpireTime;
        }
        #endregion

        #region Members
        /// <summary>
        /// Gets or sets the information for the identity.
        /// </summary>
        /// <value>
        /// The identity information.
        /// </value>
        public IdentityInfo Info { get; private set; }

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

        /// <summary>
        /// Gets the expire time.
        /// </summary>
        /// <value>
        /// The expire time.
        /// </value>
        [JsonProperty("expireTime")]
        public Int64 ActivateExpireTime { get; private set; }
        #endregion

        #region Methods
        /// <summary>
        /// Determines whether the identity has empty properties.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if the identity has empty properties; otherwise, <c>false</c>.
        /// </returns>
        public bool IsEmpty()
        {
            return string.IsNullOrEmpty(this.Info?.Id) && string.IsNullOrEmpty(this.Info?.DeviceName) &&
                string.IsNullOrEmpty(this.MPinIdHash) && string.IsNullOrEmpty(this.ActivateKey) && this.ActivateExpireTime == 0;
        }

        /// <summary>
        /// Determines whether the activation of the registration of this identity is expired.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if the activation is expired; otherwise, <c>false</c>.
        /// </returns>
        public bool IsExpired()
        {
            var now = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return this.ActivateExpireTime < now;
        }
        #endregion
    }
}
