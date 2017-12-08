using Newtonsoft.Json;

namespace Miracl
{
    /// <summary>
    /// Contains identity information
    /// </summary>
    public class IdentityInfo
    {
        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityInfo"/> class.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <param name="deviceName">Name of the device.</param>
        public IdentityInfo([JsonProperty("userId")] string id, string deviceName)
        {
            this.Id = id;
            this.DeviceName = deviceName;
        }
        #endregion

        #region Members
        /// <summary>
        /// Gets the identifier.
        /// </summary>
        /// <value>
        /// The identifier.
        /// </value>
        [JsonProperty("userId")]
        public string Id { get; internal set; }

        /// <summary>
        /// Gets the name of the device.
        /// </summary>
        /// <value>
        /// The name of the device.
        /// </value>
        public string DeviceName { get; internal set; }
        #endregion
    }
}
