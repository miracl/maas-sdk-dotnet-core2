using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace demo.Controllers
{
    public class loginController : Controller
    {
        public async Task<IActionResult> Index()
        {
            if (Request.Query != null && !string.IsNullOrEmpty(Request.Query["code"]) && !string.IsNullOrEmpty(Request.Query["state"]))
            {
                var properties = await Startup.Client.ValidateAuthorizationAsync(Request.Query);
                if (properties == null)
                {
                    return View("Error");
                }

                ClaimsPrincipal user = await Startup.Client.GetIdentityAsync();
                await Request.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
            }
            else if (!User.Identity.IsAuthenticated)
            {
                return View("Error");
            }

            ViewBag.Client = Startup.Client;

            return View();
        }
    }
}