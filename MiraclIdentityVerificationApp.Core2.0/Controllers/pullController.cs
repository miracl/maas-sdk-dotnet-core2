using Microsoft.AspNetCore.Mvc;
using Miracl;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pullController : Controller
    {
        private static Dictionary<string, Identity> StartedRegistration = new Dictionary<string, Identity>();

        public ActionResult Index()
        {
            ViewBag.ActivationStarted = false;
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string id)
        {
            ViewBag.ActivationStarted = false;
            var identity = await HomeController.Client.HandleNewIdentityPullAsync(id);

            if (identity != null && !identity.IsExpired())
            {
                ViewBag.ActivationStarted = true;
                ViewBag.Info = identity.Info;
                StartedRegistration.Add(id, identity);
            }
            else
            {
                if (!string.IsNullOrEmpty(id))
                {
                    ViewBag.Id = id;
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

                // check here if the identity is valid and if so, call ActivateIdentityAsync of the current client object
                if (identity != null)
                {
                    var resStatusCode = await HomeController.Client.ActivateIdentityAsync(identity.ActivationParams);
                    if (resStatusCode == HttpStatusCode.OK)
                    {
                        ViewBag.IsIdentityActivated = !identity.IsEmpty();
                        ViewBag.Info = identity.Info;
                        StartedRegistration.Remove(id);
                    }
                }
            }
            return View();
        }
    }
}