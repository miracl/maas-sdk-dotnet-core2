using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Miracl;
using System;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public enum UserVerificationMethod
    {
        StandardEmail,
        CustomEmail,
        FullCustomPull,
        FullCustomPush,
        FullCustomRPInitiated
    }

    public class HomeController : Controller
    {
        private static MiraclClient StandardEmailClient;
        private static MiraclClient CustomEmailClient;
        private static MiraclClient FullCustomPushClient;
        private static MiraclClient FullCustomPullClient;
        private static MiraclClient FullCustomRPInitiatedClient;
        private static UserVerificationMethod ClientMethod;
        internal static MiraclClient Client;

        #region Actions        
        public async Task<ActionResult> Index()
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

        public ActionResult CustomEmail()
        {
            SetupUserVerificationMethod(UserVerificationMethod.CustomEmail);
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> CustomEmail(string data)
        {
            await Logout();
            return RedirectToAction("CustomEmail");
        }

        public ActionResult FullCustomPush()
        {
            SetupUserVerificationMethod(UserVerificationMethod.FullCustomPush);
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> FullCustomPush(string data)
        {
            await Logout();
            return RedirectToAction("FullCustomPush");
        }

        public ActionResult FullCustomPull()
        {
            SetupUserVerificationMethod(UserVerificationMethod.FullCustomPull);
            return View("Index");
        }

        [HttpPost]
        public async Task<ActionResult> FullCustomPull(string data)
        {
            await Logout();
            return RedirectToAction("FullCustomPull");
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
                    ViewBag.ErrorMsg = "You need to enter an email which you want to start the authentication with.";
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
            CustomEmailClient?.ClearUserInfo(false);
            FullCustomPushClient?.ClearUserInfo(false);
            FullCustomPullClient?.ClearUserInfo(false);
            await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }   
        
        #endregion
    }
}
