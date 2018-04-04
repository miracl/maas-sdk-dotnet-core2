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

        public async Task<IActionResult> Index()
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            ViewBag.AuthorizationUri = await GetUrl(url);
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string Logout)
        {
            if (Logout != null)
            {
                Client.ClearUserInfo(false);
                await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

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
