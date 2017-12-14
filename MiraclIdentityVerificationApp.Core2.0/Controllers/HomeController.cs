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
        CustomEmail,
        FullCustomPull,
        FullCustomPush
    }

    public class HomeController : Controller
    {
        private static MiraclClient StandardEmailClient;
        private static MiraclClient CustomEmailClient;
        private static MiraclClient FullCustomPushClient;
        private static MiraclClient FullCustomPullClient;
        internal static MiraclClient Client;

        #region Actions
        public async Task<ActionResult> Index()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.StandardEmail);
            ViewBag.VerificationFlow = UserVerificationMethod.StandardEmail.ToString();
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string data)
        {
            await Logout();
            return RedirectToAction("Index");
        }

        public async Task<ActionResult> CustomEmail()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.CustomEmail);
            ViewBag.VerificationFlow = UserVerificationMethod.CustomEmail.ToString();
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> CustomEmail(string data)
        {
            await Logout();
            return RedirectToAction("CustomEmail");
        }

        public async Task<ActionResult> FullCustomPush()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.FullCustomPush);
            ViewBag.VerificationFlow = UserVerificationMethod.FullCustomPush.ToString();
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> FullCustomPush(string data)
        {
            await Logout();
            return RedirectToAction("FullCustomPush");
        }

        public async Task<ActionResult> FullCustomPull()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.FullCustomPull);
            ViewBag.VerificationFlow = UserVerificationMethod.FullCustomPull.ToString();
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> FullCustomPull(string data)
        {
            await Logout();
            return RedirectToAction("FullCustomPull");
        }

        #endregion

        #region Methods
        private static async Task<string> GetUrl(string url, UserVerificationMethod method)
        {
            return await GetClient(method).GetAuthorizationRequestUrlAsync(url);
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
                case UserVerificationMethod.CustomEmail:
                    if (CustomEmailClient == null)
                    {
                        CustomEmailClient = new MiraclClient(new MiraclOptions
                        {
                            ClientId = Startup.Configuration["zfa:CustomEmailClientId"],
                            ClientSecret = Startup.Configuration["zfa:CustomEmailClientSecret"],
                            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                            SaveTokens = true
                        });
                    }
                    Client = CustomEmailClient;
                    break;
                case UserVerificationMethod.FullCustomPush:
                    if (FullCustomPushClient == null)
                    {
                        // Note that in this flow we need a CustomerId too as the identity registration token is signed with it
                        FullCustomPushClient = new MiraclClient(new MiraclOptions
                        {
                            ClientId = Startup.Configuration["zfa:FullCustomPushClientId"],
                            ClientSecret = Startup.Configuration["zfa:FullCustomPushClientSecret"],
                            CustomerId = Startup.Configuration["zfa:FullCustomPushCustomerId"],
                            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                            SaveTokens = true
                        });
                    }
                    Client = FullCustomPushClient;
                    break;
                case UserVerificationMethod.FullCustomPull:
                    if (FullCustomPullClient == null)
                    {
                        FullCustomPullClient = new MiraclClient(new MiraclOptions
                        {
                            ClientId = Startup.Configuration["zfa:FullCustomPullClientId"],
                            ClientSecret = Startup.Configuration["zfa:FullCustomPullClientSecret"],
                            SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                            SaveTokens = true
                        });
                    }
                    Client = FullCustomPullClient;
                    break;
            }

            return Client;
        }

        private async Task Logout()
        {
            if (Request.Form["Logout"] == "Logout")
            {
                StandardEmailClient?.ClearUserInfo(false);
                CustomEmailClient?.ClearUserInfo(false);
                FullCustomPushClient?.ClearUserInfo(false);
                FullCustomPullClient?.ClearUserInfo(false);
                await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        }
        #endregion
    }
}
