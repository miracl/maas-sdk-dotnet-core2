using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class customEmailController : Controller
    {
        public async Task<ActionResult> Index()
        {
            ViewBag.IsIdentityActivated = false;
            if (Request.Query == null || string.IsNullOrEmpty(Request.Query["i"]) || string.IsNullOrEmpty(Request.Query["s"]))
            {
                return View();
            }

            var activateKey = Request.Query["s"];
            var hashMPinId = Request.Query["i"];

            ViewBag.Info = await HomeController.Client.GetIdentityInfoAsync(hashMPinId, activateKey);

            // apply a custom logic here for validating the identity before activating it
            if (ViewBag.Info != null)
            {
                if (await HomeController.Client.ActivateIdentityAsync(hashMPinId, activateKey) == HttpStatusCode.OK)
                {
                    ViewBag.IsIdentityActivated = true;
                }
            }

            return View();
        }
    }
}