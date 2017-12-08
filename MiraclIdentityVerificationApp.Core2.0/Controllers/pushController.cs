using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pushController : Controller
    {
        [HttpPost]
        public async Task<ActionResult> Index()
        {
            var newUserJson = new System.IO.StreamReader(Request.Body).ReadToEnd();
            var identity = HomeController.Client?.HandleNewIdentityPush(newUserJson);

            // add custom logic to decide if the identity could be activated or not, we check only if the identity is existing and not expired
            if (identity != null && !identity.IsExpired())
            {
                var respStatusCode = await HomeController.Client.ActivateIdentityAsync(identity.MPinIdHash, identity.ActivateKey);
                return new StatusCodeResult((int)respStatusCode);
            }

            return new StatusCodeResult(StatusCodes.Status400BadRequest);
        }
    }
}