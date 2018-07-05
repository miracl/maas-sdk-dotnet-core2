using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Miracl;

namespace demo.Controllers
{
    public class HomeController : Controller
    {

        public async Task<IActionResult> Index()
        {
            Startup.Client.ClearUserInfo(false);
            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var url = Request.Scheme + "://" + Request.Host.Value;
            ViewBag.AuthUrl = await Startup.Client.GetAuthorizationRequestUrlAsync(url);

            return View();
        }
    }
}
