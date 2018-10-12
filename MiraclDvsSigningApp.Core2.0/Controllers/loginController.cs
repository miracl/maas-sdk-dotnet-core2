using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Miracl;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MiraclDvsSigningApp.Controllers
{
    public class loginController : Controller
    {
        public async Task<IActionResult> Index()
        {
            if (Request.Query != null && !string.IsNullOrEmpty(Request.Query["code"]) && !string.IsNullOrEmpty(Request.Query["state"]))
            {
                var properties = await HomeController.Client.ValidateAuthorizationAsync(Request.Query);
                if (properties == null)
                {
                    return View("Error");
                }

                ClaimsPrincipal user = await HomeController.Client.GetIdentityAsync();
                await Request.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);

                var accessToken = properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken);
                if (!string.IsNullOrEmpty(accessToken))
                {
                    ViewBag.AccessToken = accessToken;
                    ViewBag.AccessTokenParsed = ParseJwt(accessToken);
                }

                var expiresAt = properties.GetTokenValue(Miracl.Constants.ExpiresAt);
                if (!string.IsNullOrEmpty(expiresAt))
                {
                    ViewBag.ExpiresAt = expiresAt;
                }
            }
            else if (!User.Identity.IsAuthenticated)
            {
                return View("Error");
            }
            
            ViewBag.Client = HomeController.Client;
            ViewBag.RedirectUri = Request.Scheme + "://" + Request.Host.Value + HomeController.Client.Options.CallbackPath;
            return View();
        }

        [HttpPost]
        public JsonResult CreateDocumentHash(string document)
        {
            var docHash = HomeController.Client.DvsCreateDocumentHash(document);
            var timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            
            // the mfa.js uses the authToken to verify the validity of the provided PIN
            var authToken = HomeController.Client.DvsCreateAuthToken(docHash);
            var documentData = new { hash = docHash, timestamp = timeStamp, authToken };

            return Json(documentData);
        }

        [HttpPost]
        public async Task<JsonResult> VerifySignature(string verificationData)
        {
            var data = JObject.Parse(verificationData);

            var mPinId = data.TryGetValue("mpinId", out JToken mPinIdValue) ? mPinIdValue.ToString() : null;
            var publicKey = data.TryGetValue("publicKey", out JToken publicKeyValue) ? publicKeyValue.ToString() : null;
            var u = data.TryGetValue("u", out JToken uValue) ? uValue.ToString() : null;
            var v = data.TryGetValue("v", out JToken vValue) ? vValue.ToString() : null;
            var docHash = data.TryGetValue("hash", out JToken docHashValue) ? docHashValue.ToString() : null;
            var ts = data.TryGetValue("timestamp", out JToken tsValue) ? tsValue.ToString() : null;
            var dtas = data.TryGetValue("dtas", out JToken dtasValue) ? dtasValue.ToString() : null;
            
            var signature = new Signature(docHash, mPinId, u, v, publicKey, dtas);
            var timeStamp = int.TryParse(ts, out int timeStampValue) ? timeStampValue : 0;
            var verificationResult = await HomeController.Client.DvsVerifySignatureAsync(signature, timeStamp);

            return Json(new { verified = verificationResult.IsSignatureValid, status = verificationResult.Status.ToString() });
        }

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }

        public static byte[] Decode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding

            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }

            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
}
