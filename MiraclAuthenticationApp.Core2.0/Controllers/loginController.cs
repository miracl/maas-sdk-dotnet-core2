using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json.Linq;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using MiraclAuthenticationApp.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace MiraclAuthenticationApp.Controllers
{
    public class loginController : Controller
    {
        public async Task<IActionResult> Index()
        {
            if (Request.Query != null && !string.IsNullOrEmpty(Request.Query["code"]) && !string.IsNullOrEmpty(Request.Query["state"]))
            {
                var properties = await HomeController.Client.ValidateAuthorization(Request.Query);
                ClaimsPrincipal user;
                if (properties != null)
                {
                    user = await HomeController.Client.GetIdentity();
                    await Request.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
                }

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
            else if(!User.Identity.IsAuthenticated)
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