using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Miracl;
using MiraclAuthenticationApp.Models;
using System.Diagnostics;
using System.Threading.Tasks;

namespace MiraclAuthenticationApp.Controllers
{
    public class HomeController : Controller
    {
        internal static MiraclClient Client;
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
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

        public async Task<ActionResult> Logout(string data)
        {
            Client?.ClearUserInfo(false);
            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index");
        }

        internal static async Task<string> GetUrl(string url)
        {
            if (Client == null)
            {
                Client = new MiraclClient(new MiraclOptions
                {
                    ClientId = Startup.Configuration["zfa:ClientId"],
                    ClientSecret = Startup.Configuration["zfa:ClientSecret"],
                    SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                    SaveTokens = true
                });
            }

            return await Client.GetAuthorizationRequestUrlAsync(url);
        }
    }
}
