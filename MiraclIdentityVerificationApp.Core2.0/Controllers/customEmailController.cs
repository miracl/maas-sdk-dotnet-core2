using Microsoft.AspNetCore.Mvc;
using Miracl;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class customEmailController : Controller
    {
        private static Dictionary<string, Identity> StartedRegistration = new Dictionary<string, Identity>();

        public async Task<ActionResult> Index()
        {
            var activationParams = HomeController.Client.ParseCustomEmailQueryString(Request.Query);
            if (activationParams != null)
            {
                var info = await HomeController.Client.GetIdentityInfoAsync(activationParams);
                if (info != null)
                {
                    var identity = new Identity(info, activationParams, 0);
                    StartedRegistration.Add(info.Id, identity);
                    ViewBag.Info = info;
                }
            }

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Activate(string id)
        {
            ViewBag.IsIdentityActivated = false;
            if (StartedRegistration.ContainsKey(id))
            {
                var identity = StartedRegistration[id];
                ViewBag.Info = identity.Info;

                // apply a custom logic here for validating the identity before activating it
                if (ViewBag.Info != null)
                {
                    var resStatusCode = await HomeController.Client.ActivateIdentityAsync(identity.ActivationParams);
                    if (resStatusCode == HttpStatusCode.OK)
                    {
                        ViewBag.IsIdentityActivated = true;
                        StartedRegistration.Remove(id);
                    }
                }
            }
            return View();
        }
    }
}