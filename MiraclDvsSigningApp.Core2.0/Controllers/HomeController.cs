using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Miracl;
using MiraclDvsSigningApp.Models;

namespace MiraclDvsSigningApp.Controllers
{
    public class HomeController : Controller
    {
        internal static MiraclClient Client;

        public IActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> Login(string email)
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            var authorizationUri = await GetUrl(url);

            // The following code is used to populate prerollid if provided during the authentication process
            if (!string.IsNullOrEmpty(email))
            {
                authorizationUri += "&prerollid=" + email;
            }
            return Redirect(authorizationUri);
        }

        public async Task<ActionResult> Logout()
        {
            if (Client != null)
            {
                Client.ClearUserInfo(false);
            }

            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index");
        }

        internal static async Task<string> GetUrl(string url)
        {
            if (Client == null)
            {
                var options = new MiraclOptions
                {
                    ClientId = Startup.Configuration["zfa:ClientId"],
                    ClientSecret = Startup.Configuration["zfa:ClientSecret"],
                    CustomerId = Startup.Configuration["zfa:CustomerId"],
                    Authority = "https://api.mpin.io", //the same authority will be used by the mfa.js
                    SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                    SaveTokens = true
                };

                //dvs scope is required by the dvs registration flow
                options.Scope.Add("dvs");

                Client = new MiraclClient(options);
            }

            return await Client.GetAuthorizationRequestUrlAsync(url);
        }
    }
}
