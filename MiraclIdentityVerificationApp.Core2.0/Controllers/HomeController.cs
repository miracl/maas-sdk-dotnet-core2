using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Miracl;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public enum UserVerificationMethod
    {
        StandardEmail,
        FullCustomRPInitiated
    }

    public class HomeController : Controller
    {
        private static MiraclClient StandardEmailClient;
        private static MiraclClient FullCustomRPInitiatedClient;
        private static UserVerificationMethod ClientMethod;
        internal static MiraclClient Client;

        #region Actions
        public ActionResult Index()
        {
            SetupUserVerificationMethod(UserVerificationMethod.StandardEmail);
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string data)
        {
            await Logout();
            return RedirectToAction("Index");
        }

        public ActionResult FullCustomRPInitiated()
        {
            SetupUserVerificationMethod(UserVerificationMethod.FullCustomRPInitiated);
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> FullCustomRPInitiated(string data)
        {
            await Logout();
            return RedirectToAction("FullCustomRPInitiated");
        }

        public async Task<ActionResult> Login(string email)
        {
            if (ClientMethod == UserVerificationMethod.FullCustomRPInitiated)
            {
                if (string.IsNullOrEmpty(email))
                {
                    ViewBag.ErrorMsg = "You need to enter an email which you want to start the custom RP initiated authentication with.";
                    return View("Error");
                }
                string device = System.Net.Dns.GetHostName();
                string authUri = await GetClient(UserVerificationMethod.FullCustomRPInitiated).GetRPInitiatedAuthUriAsync(email, device, GetAbsoluteRequestUrl());
                return Redirect(authUri);
            }

            var authorizationUri = await GetUrl(GetAbsoluteRequestUrl(), ClientMethod, email);
            return Redirect(authorizationUri);
        }

        public async Task<ActionResult> Logout(string data)
        {
            await Logout();
            return View("Index");
        }
        #endregion

        #region Methods

        private void SetupUserVerificationMethod(UserVerificationMethod method)
        {
            ClientMethod = method;
            ViewBag.VerificationFlow = method.ToString();
        }

        private static async Task<string> GetUrl(string url, UserVerificationMethod method, string email = null)
        {
            var authorizationUri = await GetClient(method).GetAuthorizationRequestUrlAsync(url);
            // The following code is used to populate prerollid if provided during the authentication process
            if (!string.IsNullOrEmpty(email))
            {
                authorizationUri += "&prerollid=" + email;
            }

            return authorizationUri;
        }

        private string GetAbsoluteRequestUrl()
        {
            return Request.Scheme + "://" + Request.Host.ToString();
        }

        private static MiraclClient GetClient(UserVerificationMethod method)
        {
            switch (method)
            {
                case UserVerificationMethod.StandardEmail:
                    if (StandardEmailClient == null)
                    {
                        StandardEmailClient = new MiraclClient(new MiraclOptions
                        {
                            ClientId = Startup.Configuration["zfa:StandardEmailClientId"],
                            ClientSecret = Startup.Configuration["zfa:StandardEmailClientSecret"],
                            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                            SaveTokens = true
                        });
                    }
                    Client = StandardEmailClient;
                    break;
                case UserVerificationMethod.FullCustomRPInitiated:
                    if (FullCustomRPInitiatedClient == null)
                    {
                        FullCustomRPInitiatedClient = new MiraclClient(new MiraclOptions
                        {
                            ClientId = Startup.Configuration["zfa:FullCustomRPInitiatedClientId"],
                            ClientSecret = Startup.Configuration["zfa:FullCustomRPInitiatedClientSecret"],
                            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                            SaveTokens = true
                        });
                    }
                    Client = FullCustomRPInitiatedClient;
                    break;
            }

            return Client;
        }

        private async Task Logout()
        {
            StandardEmailClient?.ClearUserInfo(false);
            FullCustomRPInitiatedClient?.ClearUserInfo(false);
            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        #endregion
    }
}
