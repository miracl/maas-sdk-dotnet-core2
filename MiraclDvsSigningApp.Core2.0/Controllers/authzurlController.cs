using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace MiraclDvsSigningApp.Controllers
{
    public class authzurlController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Index()
        {
            var hostUrl = Request.Scheme + "://" + Request.Host.Value; 
            return Json(new { authorizeURL = await HomeController.GetUrl(hostUrl)});
        }
    }
}