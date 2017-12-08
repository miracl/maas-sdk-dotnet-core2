using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pullController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.ActivationFinished = false;
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string id)
        {
            ViewBag.IsIdentityActivated = false;
            var identity = await HomeController.Client.HandleNewIdentityPullAsync(id);

            // check here if the identity is valid and if so, call ActivateIdentityAsync of the current client object
            if (identity != null && !identity.IsExpired())
            {
                var resStatusCode = await HomeController.Client.ActivateIdentityAsync(identity.MPinIdHash, identity.ActivateKey);
                ViewBag.IsIdentityActivated = !identity.IsEmpty() && resStatusCode == HttpStatusCode.OK;
            }

            ViewBag.ActivationFinished = true;
            return View();
        }
    }
}