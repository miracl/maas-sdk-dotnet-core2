using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using MiraclIdentityVerificationApp.Models;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
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

                var idToken = properties.GetTokenValue(OpenIdConnectParameterNames.IdToken);
                if (!string.IsNullOrEmpty(idToken))
                {
                    ViewBag.IdentityTokenParsed = ParseJwt(idToken);
                }
                var accessToken = properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken);
                if (!string.IsNullOrEmpty(accessToken))
                {
                    ViewBag.AccessTokenParsed = ParseJwt(accessToken);
                }
                var refreshToken = properties.GetTokenValue(OpenIdConnectParameterNames.RefreshToken);
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    ViewBag.RefreshTokenParsed = ParseJwt(refreshToken);
                }
                var expiresAt = properties.GetTokenValue(Miracl.Constants.ExpiresAt);
                if (!string.IsNullOrEmpty(expiresAt))
                {
                    ViewBag.ExpiresAt = expiresAt;
                }
            }
            else if (!User.Identity.IsAuthenticated)
            {
                ErrorViewModel model = new ErrorViewModel() { RequestId = Request.QueryString.Value };
                return View("Error", model);
            }

            ViewBag.Client = HomeController.Client;
            return View();
        }

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Base64UrlEncoder.Decode(parts[1]);

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }
    }
}